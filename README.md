# Inspec Profile for STIGs

Based on Security Guides found at [STIG](http://iase.disa.mil/stigs/Pages/index.aspx)

The Security Technical Implementation Guides (STIGs) and the NSA Guides are the configuration standards for DOD IA and IA-enabled devices/systems. Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the Security Technical Implementation Guides (STIGs). The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

## Develop Inspec checks:

see [read_stig_json.rb](read_stig_json.rb) for generating inspec base
from stig documentation.

## Demo

```
$ vagrant up
...
...
$ vagrant ssh -c "inspec exec /vagrant/rhel6/controls/"

Target:  local://

  ✔  V-38437: Automated file system mounting tools must not be enabled unless needed.
     ✔  Service autofs should not be enabled
     ✔  Service autofs should not be running


Profile Summary: 1 successful, 0 failures, 0 skipped
```

