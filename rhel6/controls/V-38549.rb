# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38549 - The system must employ a local IPv6 firewall.'

control 'V-38549' do
  impact 0.5
  title 'The system must employ a local IPv6 firewall.'
  desc '
The "ip6tables" service provides the system\'s host-based firewalling capability for IPv6 and ICMPv6.
'
  tag 'stig','V-38549'
  tag severity: 'medium'
  tag checkid: 'C-46107r3_chk'
  tag fixid: 'F-43497r3_fix'
  tag version: 'RHEL-06-000103'
  tag ruleid: 'SV-50350r3_rule'
  tag fixtext: '
The "ip6tables" service can be enabled with the following commands: 

# chkconfig ip6tables on
# service ip6tables start
'
  tag checktext: '
If the system is a cross-domain system, this is not applicable.

If IPv6 is disabled, this is not applicable.

Run the following command to determine the current status of the "ip6tables" service: 

# service ip6tables status

If the service is not running, it should return the following: 

ip6tables: Firewall is not running.


If the service is not running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
