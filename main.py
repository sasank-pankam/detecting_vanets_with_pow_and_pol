import hashlib
import itertools
import json
import random
import time
import uuid

import matplotlib.pyplot as plt
import networkx as nx
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import bls

MIN_TIME = 2.5
MESSAGE = 0
ENCODE = lambda x: x
DECODE = lambda x: x


RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RESET = "\033[0m"
LIGHT_GRAY = "\033[37m"
DARK_GRAY = "\033[90m"
GRAY = "\033[38;5;240m"
LIGHT_BLUE = "\033[94m"  # Light Blue
VIOLET = "\033[35m"  # Purple
BRIGHT_VIOLET = "\033[38;5;129m"


def genearte_a_location_tag():
    return uuid.uuid4().hex


class TrustedAuthority:
    def __init__(self, threshold, n_rsus):
        self.threshold = threshold
        self.n_rsus = n_rsus
        self.__private_key = ECC.generate(curve="P-256")
        self.public_key = self.__private_key.public_key()

        self.bls_ = bls.ThresholdBLS(threshold, n_rsus)
        self.signer = DSS.new(self.__private_key, "fips-186-3")

        self.rsu_keys = self.share_secret()

    def share_secret(self):
        return dict(enumerate(self.bls_.shares))
        # rsu_keys = {}
        # splits = Shamir.split(self.threshold, self.n_rsus, self.secret)
        # for i, share in enumerate(splits):
        #     rsu_keys[i] = share
        # return rsu_keys

    def get_rsu_key(self, rsu_id):
        return self.rsu_keys[rsu_id]

    def get_certificate(self, identity):
        hash_ = SHA256.new(f"{identity}".encode())
        return self.signer.sign(hash_)


class EventManager:
    def __init__(self, _max_events):
        self.maximum = _max_events
        self.events = []

        self.min_time_between_2_nodes = 2
        self.max_nodes_in_time_period = (1, 1)

    def report_event(self, event, trajectory):
        self.events.append((event, trajectory))
        if len(self.events) == self.maximum:
            self.detect_sybil_nodes()
            self.events.clear()

    def exclusion_test(self, traj1, traj2):
        rsu_s_of_1 = tuple(map(lambda x: (x[0]), traj1))
        rsu_s_of_2 = tuple(map(lambda x: (x[0]), traj2))

        y_count = 0
        for i, j in zip(rsu_s_of_1, rsu_s_of_2):
            if i == j:
                y_count += 1
                # return False

        total_length = len(rsu_s_of_2) + len(rsu_s_of_1)
        if y_count > 0.5 * len(rsu_s_of_1):
            return False

        distinct = {*rsu_s_of_1, *rsu_s_of_2}
        return len(distinct) >= int(0.7 * total_length)

    def get_graph_from_huristics(self):
        graph = nx.Graph()
        graph.add_nodes_from(range(len(self.events)))

        for i, j in itertools.combinations(range(len(self.events)), 2):
            exc_test = self.exclusion_test(self.events[i][1], self.events[j][1])
            if not exc_test:
                graph.add_edge(i, j)
        # pos = nx.spring_layout(graph, k=1)
        # nx.draw(graph, pos, node_color="cyan", node_size=1000)
        # plt.show()
        return graph

    def detect_sybil_nodes(self):
        # Find maximum cliques that overlap, indicative of Sybil behavior
        graph = self.get_graph_from_huristics()
        cliques = list(nx.find_cliques(graph))
        sybil_suspects = [clique for clique in cliques if len(clique) > 2]

        if not sybil_suspects:
            print(f"{GREEN}No sybil nodes are found.{RESET}")
        else:
            print(f"{RED}Sybil nodes are found.{RESET}")


def verify_signature(_ta_signer: DSS.DssSigScheme, _identity, _sign):
    hash_ = SHA256.new(_identity)

    try:
        _ta_signer.verify(hash_, _sign)
        return True
    except ValueError:
        return False


def sign_on_msg(private_key, msg):
    signer = DSS.new(private_key, "fips-186-3")
    hash_ = SHA256.new(f"{msg}".encode())
    return signer.sign(hash_)


def verify_a_sign(public_key, sign, msg):
    signer = DSS.new(public_key, "fips-186-3")
    hash_ = SHA256.new(f"{msg}".encode())
    try:
        signer.verify(hash_, sign)
        return True
    except ValueError:
        return False


class RSU:
    def __init__(self, rsu_id, ta: TrustedAuthority):
        self.rsu_id = rsu_id
        self.private_share = ta.get_rsu_key(rsu_id)
        self.private_key = ECC.generate(curve="p256")
        self.public_key = self.private_key.public_key()
        self.ta = ta

        self.message_store = {}

        self.adj_rsus: set[RSU] = set()

        self.cert = ta.get_certificate(self.public_key.export_key(format="raw"))

    def add_adj_rsus(self, _adj_rsu):
        self.adj_rsus.update(_adj_rsu)

    def post_new_req(self, message_list):
        decoded_list = DECODE(message_list)
        for message in message_list:
            recent_tag = message["location_tag"][-1]
            self.message_store[recent_tag] = decoded_list

    def _initial_hand_shake(self, _vehicle, _handshake_message: dict):
        if not (
            verify_a_sign(
                _vehicle.public_key,
                _handshake_message["signed_time_stamp"],
                _handshake_message["time_stamp"],
            )
            and verify_a_sign(
                self.ta.public_key,
                _handshake_message["cert"],
                _handshake_message["pub"].export_key(format="raw"),
            )
        ):
            raise Exception("Bad Request")

        location_tag = genearte_a_location_tag()
        time_stamp = time.monotonic()
        response = {
            "pub": _handshake_message["pub"],
            "time_stamp": [time_stamp],
            "location_tag": [location_tag],
        }

        sign_share = self.ta.bls_.sign_share(self.rsu_id, ENCODE(response))
        for rsu in self.adj_rsus:
            rsu.post_new_req([response])
        return ENCODE([response, sign_share])

    def verify_pow(self, _nonse, _hash, _messge):
        return _hash == hashlib.sha256(f"{_messge}{_nonse}".encode()).hexdigest()

    def _normal_hand_shake(self, _vehicle, _handshake_message: dict):
        recent_location_tag = _handshake_message[0]["trajectory"][MESSAGE][
            "location_tag"
        ][-1]
        nonse, hash_ = _handshake_message[0]["pow"]
        trajectory = _handshake_message[0]["trajectory"]

        if not self.verify_pow(nonse, hash_, json.dumps(trajectory)):
            raise Exception("pow failed")

        prev_list = self.message_store[recent_location_tag]
        _recent_t_prev_list = prev_list[: -self.ta.threshold]
        self.message_store.pop(recent_location_tag)
        sign_share = self.ta.bls_.sign_share

        shares = [
            sign_share(self.rsu_id, message)
            for other_rsu_id, message in _recent_t_prev_list
        ]

        time_stamps = [x for mes in prev_list for x in mes["time_stamp"]]
        time_stamp = time.monotonic()
        time_stamps.append(time_stamp)

        location_tags = [x for mes in prev_list for x in mes["location_tag"]]
        location_tag = genearte_a_location_tag()
        location_tags.append(location_tag)

        response = {
            "public_key": _handshake_message[0]["public_key"],
            "time_stamp": time_stamps,
            "location_tag": location_tags,
        }
        res_sign_share = sign_share(self.rsu_id, ENCODE(response))
        shares.append(res_sign_share)

        for rsu in self.adj_rsus:
            rsu.post_new_req(ENCODE([*prev_list, response]))
        return ENCODE([response, *shares])

    def recv_handshake(self, _vehicle, handshake_data):
        decoded_dict: dict = DECODE(handshake_data)
        if "time_stamp" in decoded_dict:
            return self._initial_hand_shake(_vehicle, handshake_data)
        return self._normal_hand_shake(_vehicle, handshake_data)


class Vehicle:
    def __init__(self, vehicle_id, _ta: TrustedAuthority, _em: EventManager):
        self.vehicle_id = vehicle_id
        self.trajectory = []
        self.__private_key = ECC.generate(curve="p256")
        self.public_key = self.__private_key.public_key()

        self.last_disturbed_rsu = None
        self._ta = _ta
        self._em = _em

        self.current_position = -1

        self.key_store = {}

        self._raw_public_key = self.public_key.export_key(format="raw")
        self.cert = _ta.get_certificate(self._raw_public_key)

    def generate_pow_challenge(self, message):
        """Generate a PoW challenge based on message hash"""
        nonce = 0
        target = "000"
        start = time.monotonic()
        while True:
            hashed_message = hashlib.sha256(f"{message}{nonce}".encode()).hexdigest()
            if hashed_message[: len(target)] == target:
                print(
                    f"{GRAY}took {time.monotonic() - start} seconds to perform PoW{RESET}"
                )
                return nonce, hashed_message
            nonce += 1

    def _initial_handshake(self, rsu: RSU):
        time_stamp = time.monotonic()
        handshake_msg = {
            "cert": self.cert,
            "pub": self.public_key,
            "signed_time_stamp": sign_on_msg(self.__private_key, time_stamp),
            "time_stamp": time_stamp,
        }
        response: dict = rsu.recv_handshake(self, ENCODE(handshake_msg))
        decoded_res = DECODE(response)
        pub_key = decoded_res[0]["pub"]
        decoded_res[0]["pub"] = pub_key.export_key(format="raw").hex()
        decoded_res[1] = decoded_res[1].toBytes(True).hex()
        nonse, hash_ = self.generate_pow_challenge(json.dumps(decoded_res))
        self.trajectory.append((rsu.rsu_id, (response, nonse, hash_)))

    def _normal_handshake(self, rsu: RSU):
        _message = None
        if len(self.trajectory) >= self._ta.threshold:
            _message = self.trajectory[0]

        _, (recent_traj, nonse, hash_) = self.trajectory[-1]
        private_key = ECC.generate(curve="P-256")
        public_key = private_key.public_key()

        self.key_store[rsu.rsu_id] = (private_key, public_key)

        request = {
            "trajectory": recent_traj,
            "message": _message,
            "pow": (nonse, hash_),
            "public_key": public_key.export_key(format="raw").hex(),
        }

        _signature = sign_on_msg(private_key, json.dumps(request))
        request["public_key"] = public_key
        response = rsu.recv_handshake(self, ENCODE([request, _signature]))
        decoded_res = DECODE(response)

        decoded_res[0]["public_key"] = (
            decoded_res[0]["public_key"].export_key(format="raw").hex()
        )
        for ind in range(1, len(decoded_res)):
            decoded_res[ind] = decoded_res[ind].toBytes(True).hex()
        nonse, hash_ = self.generate_pow_challenge(json.dumps(decoded_res))

        if len(self.trajectory) >= self._ta.threshold:
            self.trajectory.pop(0)
        self.trajectory.append((rsu.rsu_id, (response, nonse, hash_)))

    def handshake_with_rsu(self, rsu: RSU):
        self.last_disturbed_rsu = rsu
        if len(self.trajectory) == 0:
            return self._initial_handshake(rsu)
        return self._normal_handshake(rsu)

    def report_event_to_eventmanager(self, event):
        if len(self.trajectory) >= self._ta.threshold:
            self._em.report_event(event, self.trajectory)


class SybilNode:
    def __init__(self, n_o_fake_nodes, _ta: TrustedAuthority, em: EventManager):
        init_index = random.randint(100, 200)
        self._ta = _ta
        self.vehicle_id = "Sybil node"
        self.fake_vehicles = [
            Vehicle(init_index + i, _ta, em) for i in range(n_o_fake_nodes)
        ]
        self.em = em
        self.__current_position = -1

    @property
    def last_disturbed_rsu(self):
        return self.fake_vehicles[0].last_disturbed_rsu

    def report_event_to_eventmanager(self, event):
        for vehicle in self.fake_vehicles:
            vehicle.report_event_to_eventmanager(event)

    def handshake_with_rsu(self, rsu: RSU):
        for vehicle in self.fake_vehicles:
            vehicle.handshake_with_rsu(rsu)

    @property
    def current_position(self):
        return self.__current_position

    @current_position.setter
    def current_position(self, other):
        self.__current_position = other
        for vehicle in self.fake_vehicles:
            vehicle.current_position = other


if __name__ == "__main__":
    N_O_RSU = 10
    N_O_VEH = 4
    THRESHOLD = 3
    em = EventManager(10)
    ta = TrustedAuthority(threshold=THRESHOLD, n_rsus=N_O_RSU)
    rsu_s = [RSU(i, ta) for i in range(0, N_O_RSU)]
    vehicles = [Vehicle(i, ta, em) for i in range(N_O_VEH)]

    sybil_node = SybilNode(10, ta, em)

    vehicles = [*vehicles, sybil_node]
    adj_list_for_rsu = {
        0: [1, 2, 6],
        1: [0, 2, 5, 6],
        2: [0, 3, 1, 5],
        3: [0, 2, 4],
        4: [3, 5, 8],
        5: [2, 4, 1, 8],
        6: [0, 7, 1],
        7: [6, 8],
        8: [4, 7, 5],
    }

    for rsu, adj_rsus in adj_list_for_rsu.items():
        curr = rsu_s[rsu]
        curr.add_adj_rsus([rsu_s[x] for x in adj_rsus])

    road = {
        0: [(3, 3), (1, 0), (2, 2)],
        1: [(0, 0), (2, 1), (6, 6)],
        2: [(0, 2), (1, 1), (4, 5)],
        3: [(0, 3), (4, 4)],
        4: [(3, 4), (5, 8), (2, 5)],
        5: [(4, 8), (6, 7)],
        6: [(1, 6), (5, 7)],
    }

    startingd_points = [
        (0, 0),
        (1, 2),
        (2, 3),
        (3, 5),
    ]
    sybil_node_startinng_point = 4
    sybil_node.current_position = sybil_node_startinng_point

    for ind, junc in startingd_points:
        vehicles[ind].current_position = junc

    random.seed(10)

    for i in range(THRESHOLD + 2):
        for vehicle in vehicles:
            curr = vehicle.current_position
            possible_moves = road[curr]
            next_move, rsu_ind = possible_moves[
                random.randint(0, len(possible_moves) - 1)
            ]
            print(
                f"\nvehicle {LIGHT_BLUE}{vehicle.vehicle_id}{RESET}'s next point {BRIGHT_VIOLET}{next_move}{RESET}.",
                end="",
            )
            vehicle.current_position = next_move

            if (
                vehicle.last_disturbed_rsu
                and rsu_ind == vehicle.last_disturbed_rsu.rsu_id
            ):
                print()
                continue
            rsu_to_talk = rsu_s[rsu_ind]
            print(f"contacting {LIGHT_BLUE}{rsu_ind}{RESET}")
            vehicle.handshake_with_rsu(rsu_to_talk)

            if i >= THRESHOLD:
                vehicle.report_event_to_eventmanager("congestion")

        # input("Enter for next iteration.")
        print("\n")
