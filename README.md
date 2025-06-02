# Multi-Party Computation (MPC) Wallet (Proof of Concept)

This project implements a distributed multi-party computation (MPC) wallet in Go. It allows for distributed key generation and signing of messages using threshold ECDSA, where a minimum number of parties must cooperate to perform cryptographic operations.

**Please note:** This project is a **Proof of Concept (PoC)** and is provided for experimental purposes only.

## Project Structure

The project consists of the following main components:

- `cmd/node/main.go`: The entry point for the MPC wallet node application. It handles configuration loading, network setup, and interaction with the wallet logic.
- `internal/network/network.go`: Implements the network communication layer for the MPC nodes, enabling them to send and receive `Envelope` messages.
- `internal/wallet/wallet.go`: Contains the core MPC wallet logic, including distributed key generation (`keygen`) and signing (`sign`) functionalities using the `tss-lib` library.
- `internal/wallet/wallet_test.go`: Provides unit and integration tests for the wallet's key generation and signing processes.

## Getting Started

### Prerequisites

- Go (version 1.22 or higher)

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/example/mpc-wallet.git
cd mpc-wallet
```

2. **Download dependencies:**

```bash
go mod tidy
```

3. **Build the node executable:**

```bash
go build -o node ./cmd/node
```

## Configuration

The application uses a YAML configuration file. An example `configs/common.yaml` might look like this:

```yaml
node_id: 1 # This will be overridden by the --node_id flag for each terminal
peers:
  1: "127.0.0.1:18011"
  2: "127.0.0.1:18012"
  3: "127.0.0.1:18013"
data_dir: "./data" # Directory to store key shares
```

Make sure to create a `configs` directory and this `common.yaml` file.

## Running the Application

To run the MPC wallet, you need to start three separate node instances, each in its own terminal. Each instance will participate in the distributed key generation and signing process.

1. **Open three separate terminal windows.**

2. **In Terminal 1, run Node 1:**

```bash
./node --config configs/common.yaml --node_id 1
```

3. **In Terminal 2, run Node 2:**

```bash
./node --config configs/common.yaml --node_id 2
```

4. **In Terminal 3, run Node 3:**

```bash
./node --config configs/common.yaml --node_id 3
```

Once all three nodes are running, they will automatically perform a distributed key generation. After key generation is complete, you can type a message into any of the node's terminals and press Enter to initiate a distributed signing process. The resulting `r` and `s` values of the signature will be printed.

## Running Tests

To run the project's tests, navigate to the project root and execute the following command:

```bash
go test -v ./internal/wallet
```

This will run the tests for the `internal/wallet` package, which includes tests for key generation and signing.