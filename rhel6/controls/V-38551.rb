# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38551 - The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.'

control 'V-38551' do
  impact 0.5
  title 'The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.'
  desc '
The "ip6tables" service provides the system\'s host-based firewalling capability for IPv6 and ICMPv6.
'
  tag 'stig','V-38551'
  tag severity: 'medium'
  tag checkid: 'C-46109r3_chk'
  tag fixid: 'F-43499r2_fix'
  tag version: 'RHEL-06-000106'
  tag ruleid: 'SV-50352r3_rule'
  tag fixtext: '
The "ip6tables" service can be enabled with the following commands:

# chkconfig ip6tables on
# service ip6tables start
'
  tag checktext: '
If the system is a cross-domain system, this is not applicable.

If IPV6 is disabled, this is not applicable.

Run the following command to determine the current status of the "ip6tables" service:

# service ip6tables status

If the service is not running, it should return the following:

ip6tables: Firewall is not running.


If the service is not running, this is a finding.
'

# START_DESCRIBE V-38551
  only_if { kernel_module('ipv6').loaded? }
  describe service('ip6tables') do
    it { should be_enabled }
    it { should be_running }
  end
# END_DESCRIBE V-38551

end
