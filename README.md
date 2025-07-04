# Security Operations Dashboard (SIEM Lite)

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Chart.js](https://img.shields.io/badge/Charts-Chart.js-red?style=for-the-badge&logo=chart.js&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-000000?style=for-the-badge&logo=security&logoColor=white)
![SecOps](https://img.shields.io/badge/Domain-SecOps-darkblue?style=for-the-badge)
![SIEM](https://img.shields.io/badge/Concept-SIEM-blue?style=for-the-badge)

## Project Overview

The **Security Operations Dashboard (SIEM Lite)** is a sophisticated, web-based application designed to simulate the core functionalities of a Security Information and Event Management (SIEM) system. This project demonstrates the critical process of collecting (simulated), aggregating, analyzing, and visualizing security event data to provide a centralized, interactive, and real-time (simulated) view of an organization's security posture. It's a foundational step towards understanding complex security operations and incident response.

## Key Features

* **Centralized Security Monitoring (Simulated SIEM):**
    * Acts as a single pane of glass for all incoming security events, mimicking a real-world SIEM.
    * Backend continuously generates diverse, realistic-looking simulated security event data (e.g., login attempts, malware detections, network scans, file access, firewall blocks, unauthorized access attempts).
* **Dynamic Data Visualization:**
    * Presents key security metrics through interactive and visually appealing charts powered by **Chart.js**.
    * **Events by Type Chart:** Bar chart illustrating the distribution of various security event categories, highlighting common threats.
    * **Events by Severity Chart:** A clear pie chart breaking down events by their severity levels (Critical, High, Medium, Low), aiding in prioritization.
    * **Top Attacking IPs Chart:** Horizontal bar chart identifying source IPs generating the most suspicious activity, crucial for threat intelligence.
* **Threat Intelligence & Alerting:**
    * Prominently displays a dedicated section for **Recent Critical Alerts**, ensuring immediate visibility of high-priority incidents.
    * Provides high-level summary cards for **Total Events**, **Critical Alerts**, and **High Severity** events for a quick security overview.
* **Interactive Event Log & Filtering:**
    * Features a comprehensive tabular display of all simulated security events.
    * Empowers analysts with dynamic filtering capabilities by both **severity** and **event type**, allowing for targeted investigation and efficient incident triage.
* **Secure Access & Authentication:**
    * Implements a master password login screen to secure access to the sensitive dashboard.
    * Supports a first-time setup mode for the master password, ensuring secure initialization.
* **Responsive User Interface:**
    * Designed with a modern, dark-themed aesthetic that enhances readability and reduces eye strain during prolonged monitoring.
    * The entire dashboard layout adapts gracefully to various screen sizes (desktop, tablet, mobile), ensuring optimal usability and a professional appearance on any device.
* **Full-Stack Application:**
    * Combines a robust **Python Flask backend** for sophisticated data simulation, aggregation, and API serving.
    * Paired with a dynamic **HTML/CSS/JavaScript frontend** for rich visualization and intuitive user interaction.

## Technologies Used

* **Python 3.x:** Core language for backend logic, data simulation, and event processing.
* **Flask:** A lightweight and flexible Python web framework, used for building the backend application and exposing RESTful API endpoints.
* **`pandas`:** Essential for efficient structuring, manipulation, and aggregation of simulated security event data.
* **`numpy`:** Utilized for numerical operations and random data generation within the simulation.
* **`hashlib` & `os`:** Employed for secure master password hashing (SHA256) and robust session management, ensuring dashboard security.
* **HTML5, CSS3, JavaScript:** Form the foundation of the interactive and responsive frontend user interface.
* **Chart.js:** A powerful JavaScript library used for creating the dynamic, interactive, and visually appealing security charts.
* **`fetch` API:** For asynchronous communication between the frontend JavaScript and the Flask backend API endpoints.
* **Font Awesome:** Integrated for scalable vector icons, enhancing the visual clarity and professional appearance of the dashboard.

## How to Download and Run the Project

### 1. Prerequisites

* **Python 3.x:** Ensure Python 3.x is installed on your system. Download from [python.org](https://www.python.org/downloads/). During installation, make sure to check "Add Python.exe to PATH".
* **`pip`:** Python's package installer, which comes with Python.
* **Git:** Ensure Git is installed on your system. Download from [git-scm.com](https://git-scm.com/downloads/).
* **VS Code (Recommended):** For a smooth development experience with its integrated terminal.

### 2. Download the Project

1.  **Open your terminal or Git Bash.**
2.  **Clone the repository:**
    ```bash
    git clone [https://github.com/](https://github.com/)AtharvaMeherkar/Security-Operations-Dashboard.git
    ```
3.  **Navigate into the project directory:**
    ```bash
    cd Security-Operations-Dashboard
    ```

### 3. Setup and Installation

1.  **Open the project in VS Code:**
    ```bash
    code .
    ```
2.  **Open the Integrated Terminal in VS Code** (`Ctrl + ~`).
3.  **Create and activate a virtual environment (highly recommended):**
    ```bash
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```
    You should see `(venv)` at the beginning of your terminal prompt, indicating the virtual environment is active.
4.  **Install the required Python packages:**
    ```bash
    pip install Flask pandas matplotlib
    ```
    *(Note: `matplotlib` is installed for potential local plotting/data generation in the backend, although charts are rendered on the frontend with Chart.js.)*

### 4. Execution

1.  **Ensure your virtual environment is active** in the VS Code terminal.
2.  **Set the Flask application environment variable:**
    ```bash
    # On Windows:
    $env:FLASK_APP = "app.py"
    # On macOS/Linux:
    export FLASK_APP=app.py
    ```
3.  **Run the Flask development server:**
    ```bash
    python -m flask run
    ```
    * **Default Master Password:** On the very first run, if no master password is set, the backend will automatically set it to: `adminpass`. You will see a warning message in your terminal confirming this.
    * The server will start and be accessible at `http://127.0.0.1:5000`.

4.  **Open your web browser** and go to `http://127.0.0.1:5000` (or `http://localhost:5000`). This will automatically redirect you to the login page.
5.  **Log in:** Enter the master password (`adminpass` by default) to access the dashboard.
6.  **Interact with the Dashboard:**
    * Observe the high-level summary cards and the dynamic charts updating with simulated data.
    * Use the filter dropdowns (Severity, Type) above the "Event Log" table and click "Apply Filters" to see dynamic filtering in action.
    * Click the "Logout" button in the header to return to the login screen.

## Screenshots

![image](https://github.com/user-attachments/assets/369819d7-440a-41ef-be48-6ff73bb21529)

![image](https://github.com/user-attachments/assets/3c4b4dea-9491-4cda-b1f2-f38d7fdd0179)

![image](https://github.com/user-attachments/assets/a199cbd0-ae64-4f3e-ad74-0b694f6efcf9)

![image](https://github.com/user-attachments/assets/b3ba499d-c1cf-4233-9576-257005bd937c)

![image](https://github.com/user-attachments/assets/cb277287-940a-4222-9240-5ee6ca90eb9f)



## What I Learned / Challenges Faced

* **Security Operations (SecOps) & SIEM Concepts:** Gained invaluable hands-on experience in the fundamental principles of SIEM systems, focusing on how security event data is aggregated, analyzed, and presented for operational insights and incident response.
* **Data Aggregation & Visualization:** Mastered the process of generating and processing simulated security events, then effectively visualizing complex security metrics using interactive charts (Chart.js) for enhanced readability and decision-making.
* **Threat Intelligence & Alerting:** Understood the critical importance of identifying and prominently displaying high-priority alerts, and how filtering capabilities empower security analysts in focused threat investigations.
* **Full-Stack Security Application Development:** Successfully designed and built a complete web application, seamlessly integrating a Python Flask backend (for data simulation and API serving) with a dynamic HTML/CSS/JavaScript frontend (for rich visualization and intuitive user interaction).
* **User Authentication & Session Management:** Implemented a secure login mechanism to protect dashboard access, including robust handling of user sessions in Flask.
* **Data Filtering & Interactivity:** Developed sophisticated functionalities for dynamically filtering and interacting with event logs, significantly enhancing the usability and analytical power of the dashboard.
* **Modern UI/UX for Security Tools:** Focused on crafting an attractive, dark-themed, and highly responsive user interface tailored for security professionals, emphasizing clarity, usability, and a professional aesthetic.
