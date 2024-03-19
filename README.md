# Hyperalerts

## Overview

This project focuses on analyzing network traffic to detect phases of a cyber attack. Utilizing tools like Snort for traffic capture and analysis, Tranalyzer for detailed traffic flow analysis, and MongoDB for storing and querying data, the system automates the process of converting traffic logs into actionable intelligence. The core of this system is its ability to generate hyper-alerts from correlated data across different network events.

## Directory Structure

The project is organized into several directories, each serving a specific purpose within the architecture:

- `Conector S2M`: Houses the `S2m.py` script which monitors a directory for new Snort logs converted to JSON, automatically inserting them into MongoDB for further analysis.
- `Correlador`: Contains the `Hyperalert.py` script, which correlates data from MongoDB to generate hyper-alerts.
- `modelo vista controlador (MVC)`: Implements the MVC design pattern to organize the project's structure. This includes:
  - `Controlador.py`: Acts as the controller, managing the flow of data between the model and view.
  - `vista.py`: Provides the view, presenting data to the user and receiving user inputs.
- `MongoDB`: This directory is intended for MongoDB database files. It includes BSON and JSON metadata files for managing collections and documents within the database, such as `system.version.bson`, `alertas.bson`, and `flow.bson`, along with their corresponding metadata `.json` files.

## Workflow

1. **Traffic Capture and Analysis**: Network traffic is captured and analyzed by Snort, with logs being converted to JSON format.
2. **Data Insertion**: The `S2m.py` script watches for new JSON-formatted Snort logs and inserts them into MongoDB.
3. **Hyper-alert Generation**: The `Hyperalert.py` script correlates events and data within MongoDB to generate hyper-alerts, signifying detected phases of a cyber attack.
4. **MVC Architecture**: The MVC components (`Controlador.py` and `vista.py`) manage data flow and user interaction, allowing for dynamic query and visualization of the analysis results.

## Installation and Configuration

### Prerequisites

- MongoDB
- Snort
- Tranalyzer

Refer to the installation guides on Tranalyzer's official website for setting up Tranalyzer and its plugins:
- Tranalyzer Installation Guide: [Tranalyzer Installation Guide](https://tranalyzer.com/tutorial/installation)
- Plugins Overview: [Plugins Overview](https://tranalyzer.com/tutorial/pluginsoverview)

### MongoDB Setup

Execute `apt-get install mongo` to install MongoDB on your system.

### Custom Scripts

- `S2m.py` monitors a directory for new JSON files and inserts them into MongoDB.
- `Hyperalert.py` queries MongoDB, correlates data, and generates hyper-alerts.

