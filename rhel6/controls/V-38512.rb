# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38512 - The operating system must prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.'

control 'V-38512' do
  impact 0.5
  title 'The operating system must prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.'
  desc '
The "iptables" service provides the system\'s host-based firewalling capability for IPv4 and ICMP.
'
  tag 'stig','V-38512'
  tag severity: 'medium'
  tag checkid: 'C-46069r2_chk'
  tag fixid: 'F-43459r2_fix'
  tag version: 'RHEL-06-000117'
  tag ruleid: 'SV-50313r2_rule'
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

# START_DESCRIBE V-38512
  describe service('iptables') do
    it { should be_enabled }
    it { should be_running }
  end
# END_DESCRIBE V-38512

end
