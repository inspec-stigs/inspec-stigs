# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38560 - The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.'

control 'V-38560' do
  impact 0.5
  title 'The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.'
  desc '
The "iptables" service provides the system\'s host-based firewalling capability for IPv4 and ICMP.
'
  tag 'stig','V-38560'
  tag severity: 'medium'
  tag checkid: 'C-46118r2_chk'
  tag fixid: 'F-43508r2_fix'
  tag version: 'RHEL-06-000116'
  tag ruleid: 'SV-50361r2_rule'
  tag fixtext: '
The "iptables" service can be enabled with the following commands:

# chkconfig iptables on
# service iptables start
'
  tag checktext: '
If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the "iptables" service:

# service iptables status

If the service is not running, it should return the following:

iptables: Firewall is not running.


If the service is not running, this is a finding.
'

# START_DESCRIBE V-38560
  describe service('iptables') do
    it { should be_enabled }
    it { should be_running }
  end
# END_DESCRIBE V-38560

end
