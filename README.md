# Sybil Attack Detection in VANETs

Implementation of a Sybil attack detection system for Vehicular Ad-hoc Networks (VANETs) using threshold BLS signatures and trajectory analysis.

## Overview

This system implements a distributed Sybil attack detection mechanism for VANETs using:
- Threshold BLS signature scheme for secure communication
- Trajectory-based exclusion tests for Sybil detection
- Proof-of-Work challenges for vehicle authentication
- Graph-based analysis for identifying Sybil behavior patterns

## Components

- **TrustedAuthority**: Manages cryptographic keys and certificate distribution
- **RSU**: Road Side Units that authenticate vehicles and relay messages
- **Vehicle**: Legitimate vehicles that communicate with RSUs
- **SybilNode**: Malicious nodes that attempt to create fake identities
- **EventManager**: Analyzes trajectories and detects Sybil attacks

## Usage

```bash
python main.py
```

## Dependencies

- matplotlib
- networkx
- pycryptodome
- bls12381 (included)

## Architecture

The system simulates a vehicular network with:
- Multiple RSUs connected in a mesh topology
- Legitimate vehicles moving between RSUs
- Sybil nodes attempting to create fake identities
- Event-based detection using trajectory analysis

## Detection Method

1. Vehicles authenticate with RSUs using threshold BLS signatures
2. Trajectory data is collected and analyzed
3. Exclusion tests identify overlapping trajectories
4. Graph analysis detects Sybil behavior patterns
5. Maximum clique detection identifies coordinated Sybil attacks 