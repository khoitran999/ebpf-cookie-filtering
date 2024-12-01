# eBPF Cookie Filter

An advanced system utilizing eBPF (Extended Berkeley Packet Filter) technology to filter and monitor cookies at the kernel level, complemented by a user-space daemon and an interactive Django-based dashboard for management and visualization.

## Features

- **Kernel-Level Filtering**: Efficiently filter cookies using eBPF for minimal overhead and high performance.
- **User-Space Daemon**: Python-based management of eBPF programs and communication with the kernel.
- **Dashboard Interface**: Django-powered web interface for monitoring and configuring filters.
- **Configurable Rules**: Flexible configuration options to define filtering logic and policies.

---

## Repository Structure

```
ebpf-cookie-filter/
├── config/          # Configuration files for the filter
├── dashboard/       # Django-based web dashboard for management on port 8000
├── ebpf_module/     # eBPF programs and kernel-level logic
└── user_daemon/     # Python user-space daemon for eBPF interactions
```

### `config/`
Contains configuration files for setting up filtering rules, thresholds, and other system settings.

### `dashboard/`
Holds the Django project for the dashboard, which provides a web interface to view and manage the cookie filtering system.

### `ebpf_module/`
Includes the core eBPF programs that define the filtering logic executed in the kernel.

### `user_daemon/`
Contains the Python-based user-space daemon responsible for loading eBPF programs, handling communication with the kernel, and managing the system.

---

## Getting Started

### Prerequisites

- **Linux Kernel**: Version 5.0 or later with eBPF support enabled.
- **Dependencies**:
  - `clang` and `llvm` for compiling eBPF programs.
  - `libbpf` for eBPF interaction.
  - `Python 3.8+` for the daemon and dashboard.
  - `pip` for Python package management.
  -  And other dependencies listed in the respective `requirements.txt` files.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/QLe13/ebpf-cookie-filter.git
   cd ebpf-cookie-filter
   ```

#### Set Up the eBPF Module

2. Build and load the eBPF program:
   ```bash
   cd ebpf_module
   make
   sudo ./load_ebpf
   ```

#### Set Up the User Daemon

3. Navigate to the `user_daemon` directory and install dependencies:
   ```bash
   cd ../user_daemon
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

4. Run the user-space daemon:
   ```bash
   python user_daemon.py
   ```

#### Set Up the Dashboard

5. Navigate to the `dashboard` directory and install dependencies:
   ```bash
   cd ../dashboard
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

6. Apply database migrations and run the server:
   ```bash
   cd /dashboard_app
   python manage.py migrate
   python manage.py runserver
   ```

7. Access the dashboard at `http://localhost:8000`.

---

## Usage

1. Define filtering rules in the `config/` directory.
2. Start the eBPF program using the user-space daemon.
3. Access the Django dashboard at `http://localhost:8000` to monitor and manage filters.
4. Review logs and performance metrics via the dashboard or system logs.

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m "Add YourFeature"`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

Let me know if you'd like further customization or additional examples in the README!