
# vManage APIs for Security Events

# Objective 

*   How to use vManage APIs to collect security events

# Requirements

To use this code you will need:

* Python 3.7+
* vManage user login details. (User should have privilege level to read events)

# Install and Setup

- Clone the code to local machine.

```
git clone https://github.com/suchandanreddy/sdwan-security-events.git
cd sdwan-security-events
```

- Setup Python Virtual Environment (requires Python 3.7+)

```
python3.7 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

- Create **vmanage_login.yaml** using below sample format to provide the login details of vManage

## Example:

```
# vManage Connectivity Info
vmanage_host:
vmanage_port:
vmanage_username:
vmanage_password:
```

## Sample Outputs

```
(venv) python3 security-events.py
Please enter start date(YYYY-MM-DD): 2020-03-01
Please enter end date(YYYY-MM-DD): 2020-04-29

Created security events file Security Events 2020-04-30.xlsx
```
