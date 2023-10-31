# cscs-keygen

Python script to automate fetching a new SSH keypair for CSCS infrastructure. It relies on credentials stored in a cloud-based password manager, like Bitwarden or 1Password.

## Setup

### Prerequisites

- Python 3.10 with the dependencies listed in `requirements.txt` installed
- An account with a supported password manager. Currently: [Bitwarden](https://bitwarden.com), [1Password](https://1password.com/)
  - The password manager must be configured to store the following information:
    - The username of your CSCS account
    - The password of your CSCS account
    - The configured TOPT secret of your CSCS account
- The command-line interface (CLI) of the password manager of your choice:
  - [Bitwarden](https://bitwarden.com/help/article/cli/)
  - [1Password](https://support.1password.com/command-line-getting-started/)
- (optional) A virtual environment with `venv` or `pipenv` (or any other similar utility of your choice)

> **Note**
>
> Bitwarden's free plan does **not** include the option to store TOTP secrets. You will need to upgrade to a [paid plan](https://bitwarden.com/pricing/) to use this script with Bitwarden.

## Usage

### Quickstart

1. Clone this repository
2. Make sure you have the CLI of your password manager installed and configured
3. Make sure you are in the correct Python environment (it is recommended to avoid system-wide installations)
4. Install the package with `pip install .`
5. Run the script with `cscs-keygen --help` to see the available options

For more details, check out the [docs](https://github.com/empa-scientific-it/cscs-keygen/wiki) (🚧 WIP) of this project.
