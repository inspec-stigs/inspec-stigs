# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38606 - The tftp-server package must not be installed unless required.'

control 'V-38606' do
  impact 0.5
  title 'The tftp-server package must not be installed unless required.'
  desc '
Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.
'
  tag 'stig','V-38606'
  tag severity: 'medium'
  tag checkid: 'C-46164r1_chk'
  tag fixid: 'F-43554r1_fix'
  tag version: 'RHEL-06-000222'
  tag ruleid: 'SV-50407r2_rule'
  tag fixtext: '
The "tftp-server" package can be removed with the following command: 

# yum erase tftp-server
'
  tag checktext: '
Run the following command to determine if the "tftp-server" package is installed: 

# rpm -q tftp-server


If the package is installed, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
