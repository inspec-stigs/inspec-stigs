# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38444 - The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets.'

control 'V-38444' do
  impact 0.5
  title 'The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets.'
  desc '
In "ip6tables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
'
  tag 'stig','V-38444', 'ipv6'
  tag severity: 'medium'
  tag checkid: 'C-45999r2_chk'
  tag fixid: 'F-43389r3_fix'
  tag version: 'RHEL-06-000523'
  tag ruleid: 'SV-50244r2_rule'
  tag fixtext: '
To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/ip6tables":

:INPUT DROP [0:0]

Restart the IPv6 firewall:

# service ip6tables restart
'
  tag checktext: '
If IPv6 is disabled, this is not applicable.

Inspect the file "/etc/sysconfig/ip6tables" to determine the default policy for the INPUT chain. It should be set to DROP:

# grep ":INPUT" /etc/sysconfig/ip6tables

If the default policy for the INPUT chain is not set to DROP, this is a finding.
'

# START_DESCRIBE V-38444
  only_if { kernel_module('ipv6').loaded? }

  describe ip6tables do
    it { should have_rule('-P INPUT DROP') }
  end
# END_DESCRIBE V-38444

end
