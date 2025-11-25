# GTI MISP Threat Intel Data Connector

This project automates the process of pulling Threat Intelligence from Google Threat Intelligence and importing it into your MISP instance. It can be configured to run as a one-time import or on a periodic schedule to keep your MISP instance updated with the latest GTI data.

Attention: Configure the connector in the [Google Threat Intelligence interface](https://www.virustotal.com/gui/technology-integrations/third-party-to-vt) prior to starting ingestion.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd gti-misp-connector
    ```

2.  **Configure Environment Variables:**
    Create a `.env` file in the root of the project and add the following variables:
    ```ini
    GTI_APIKEY=YOUR_GTI_API_KEY
    LIMIT=10
    MISP_URL=YOUR_MISP_URL
    MISP_APIKEY=YOUR_MISP_API_KEY
    MISP_SSL=False
    ```
    Replace the placeholder values with your actual API keys and URLs.
    *   `LIMIT`: Controls the number of messages fetched from GTI in a single API call. The recommended value is 10 and it can't be greater than 40.
    *   `MISP_SSL`: Controls whether to use SSL verification when connecting to MISP (defaults to False).

## Running Locally

1.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
    *To deactivate, simply run: `deactivate`*

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the connector:**
    *   **Run once:**
        ```bash
        python src/main.py
        ```
    *   **Run periodically (e.g., every 60 seconds):**
        ```bash
        python src/main.py --schedule 60
        ```

## Running with Docker

1.  **Build the Docker image:**
    ```bash
    docker build --no-cache -t misp-connector .
    ```

2.  **Run the Docker container:**
    *   **Run once:**
        ```bash
        docker run --env-file .env misp-connector
        ```
    *   **Run periodically (e.g., every 60 seconds):**
        ```bash
        docker run --env-file .env misp-connector --schedule 60
        ```
