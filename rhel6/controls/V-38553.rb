# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38553 - The operating system must prevent public IPv6 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.'

control 'V-38553' do
  impact 0.5
  title 'The operating system must prevent public IPv6 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.'
  desc '
The "ip6tables" service provides the system\'s host-based firewalling capability for IPv6 and ICMPv6.
'
  tag 'stig','V-38553'
  tag severity: 'medium'
  tag checkid: 'C-46111r3_chk'
  tag fixid: 'F-43501r2_fix'
  tag version: 'RHEL-06-000107'
  tag ruleid: 'SV-50354r3_rule'
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

# START_DESCRIBE V-38553
  only_if { kernel_module('ipv6').loaded? }
  describe service('ip6tables') do
    it { should be_enabled }
    it { should be_running }
  end
# END_DESCRIBE V-38553

end
