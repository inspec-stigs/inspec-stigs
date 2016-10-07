# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38686 - The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.'

control 'V-38686' do
  impact 0.5
  title 'The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.'
  desc '
In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
'
  tag 'stig','V-38686'
  tag severity: 'medium'
  tag checkid: 'C-46248r1_chk'
  tag fixid: 'F-43635r1_fix'
  tag version: 'RHEL-06-000320'
  tag ruleid: 'SV-50487r1_rule'
  tag fixtext: '
To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in "/etc/sysconfig/iptables": 

:FORWARD DROP [0:0]
'
  tag checktext: '
Run the following command to ensure the default "FORWARD" policy is "DROP": 

grep ":FORWARD" /etc/sysconfig/iptables

The output must be the following: 

# grep ":FORWARD" /etc/sysconfig/iptables
:FORWARD DROP [0:0]

If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
