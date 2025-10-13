# Harm0niz3r

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![HarmonyOS](https://img.shields.io/badge/HarmonyOS-Next%205.0%2B-lightgrey.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

A powerful security assessment and application interaction framework for HarmonyOS Next (5.0+).
Harm0niz3r enables researchers to interact with and analyze applications from a controlled rogue app, allowing enumeration of internal components and permissions in a simple and extensible way.

# Quickstart

## Setup

Download or clone this Github repo:

```bash
git clone https://github.com/DEKRA-Cybersecurity/Harm0niz3r/
```

### Client Setup

First step is to install Harm0niz3r client in the target device, it can be done through Huawei DevEco Studio (main HOS development tool, like XCode for *OS) or by installing the `.hap` package with hdc command:

```bash
hdc app install harm0niz3r.hap
```

Once installed, the icon will be visible from app menu in HOS.

### Server Setup

In order to use Harm0niz3r, `hdc` command is required to be instaled in the system (and named after `hdc`, if command is spelled in other way, just change config in `Harm0niz3r.py`). Then run the server:

```bash
python3 Harm0niz3r.py
```

## Connection

Client and server must be connected to have its functionality fully available. To connect, first allow port forwarding for `tcp:51337` from server host:

```bash
hdc fport tcp:51337 tcp:51337
```

Then from Harm0niz3r CLI run the `connect` command (ensure the client is listening, 51337 is the default port and can be seen in the GUI). After that, *MARCO-POLO* handshake will be performed and connection should be stablished.

> If status is failed and connection is not stablished, make sure port forwarding is being applied and re-run both client and server.

## Usage

Both client GUI and server CLI can be useg to perform many operations. With `help` command in CLI all possibilities are shown.

# Development

This section is meant to be a development guide for anyone contributing.

## Structure

The project is divided in two main parts: Server and Client.

### Server

The server is written in python3 and provides direct interaction with the device via `hdc`. It provides a CLI, however requires the target device to be connected to PC.

### Client (App)

Apart from the server, a native application is provided. This application must be installed in the target device, allowing to perform operations in a simpler way.

## Connection and Communication

When `connect` command is sent from CLI, TCP socket is opened (by default on port `51337`). If successful, *MARCO-POLO* handshake is performed in order to start the session:

1. Server sends `MARCO \n\n` command to client.
2. If client responds with `POLO`, the connection is stablished.

```ts
// Handshake side in client
if (txt === 'MARCO') {
    await cli.send({ data: 'POLO' });
    this.status = `Console connected on ${this.port}`;
    hilog.info(0x0000, 'AppLog', 'Responded with POLO for MARCO handshake.');
    return;
}
```

Once connected, a thread will continuously read from connection so client can send message requests to server or vice-versa.

### Client to server communication

Usually the client will request server to perform operations or just provide some information. For this purpose client implements `sendToPcClient` method which sends a message string.

The messages have generally the following structure: `COMMAND_REQUEST:<command>`, so the first part is the type of message and the second the data itself, separated by a colon.

The server on its side process those messages in `_receive_loop` method, where are declared those message types and actions associated to them.

```ts
if decoded_data.startswith('COMMAND_REQUEST:'):
    command_payload = decoded_data[len('COMMAND_REQUEST:'):].strip()
    self._print_message("INFO", f"Received command request from app: '{command_payload}'")
    # Parse and execute the command from the app
    self._process_app_command_request(command_payload)
```
> Example statement for the `COMMAND_REQUEST` message type in `_receive_loop` method.

### Server to client communication

Sending data from server to client is a similar process than the previous. The method used by the server is `send_data_to_app` and messages have the same structure as seen. However include '` \n\n`' as ending trail.

The inclusion of and ending trail is necessary as responses from server may be longer. So for the cases where a message is sent over more than one TCP package, the client implements a buffered reception which listens until that ending trail is received.

The method used by client to receive raw packets is `handlePacket` which after receive '` \n\n`' calls `processFullMessage` which actually interprets the message.

## Adding features

Adding new commands or messages is quite simple:

1. Create callback method which implements the new command's feature:

```python
def example_feature_server(self):
    """A new incredible feature in the server."""
    
    return "Testing 123..."
```
> Callback example in server.

2. Add entry in receive method (either server or client) for the system to be able to interpret and perform the new feature.

```python
def _process_app_command_request(self, command_payload: str):

        [...]

        if cmd == "app_info": [...]
        elif cmd == "apps_list": [...]
        elif cmd == "app_surface": [...]
        elif cmd == "udmf_query_single_app": [...]
        elif cmd == "udmf_query_all_apps": [...]
        elif cmd == 'app_visible_abilities': [...]
        elif cmd == 'invoke_with_want': [...]

        elif cmd == 'new_feature':

            example_feature_server()

        else: [...]
```
> Example to add new command to server command process method.

3. Use new feature (button in Client, command in CLI...)

> Depending on the functionality implemented the command will be defined in one function or another, the above process is just a simplified view. For instance, if wanted to perform the same `new_feature` command from CLI (which is recommended) should also be specified in `start_console`.
> Or if the feature returns a value back to be displayed on the app, the callback will define a message type and that message should be properly defined in app.

# Authors

- Jorge Wallace Ruiz
- Pablo Cáceres Gaitán

As part of DEKRA's cybersecurity team.

## License

Harm0niz3r is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.

