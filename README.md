ansible-playbook-ubuntu
=========

For automated initialization settings in Ubuntu 18.04 and others

Requirements
------------

- ansible (>=2.5.x)
- Playbooks must be executed by not ubuntu account(ex. root) because this code remove ubuntu account, home directory

How to use
--------------

      # apt update; apt install ansible
      # git clone http://github.ebaykorea.com/CloudPlatform/ansible-playbook-ubuntu
      # cd ansible-playbook-ubuntu/
      # ansible-playbook playbooks/setting.yml

Pre-checks
----------------

Before run ansible-playbook, pre-checking to using these commands:

    $ ansible localhost -m ping
      localhost | SUCCESS => {
        "changed": false,
        "ping": "pong"
      }

Each Roles
----------------

- common:
  - add administrator, default user
  - set DNS, NTP, Proxy, mirrorlist
  - set Timezone (Asia/Seoul)
  - remove unnecessary file and ubuntu account
- ssh:
  - enable PasswordAuthentication
  - disable PermitRootLogin
  - restart ssh service
- sssd(LDAP):
  - install sssd package
  - set sssd.conf
  - set metaconfig.py (for apply ebay`s LDAP policy & etc...)
- pam:
  - set PAM(Pluggable Authentication Modules) daemons for password complicated, etc ...
- tuning:
  - set TCP Port Range for 1024 to 65499

License
-------

eBay Korea Cloud Team
