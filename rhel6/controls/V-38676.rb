# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38676 - The xorg-x11-server-common (X Windows) package must not be installed, unless required.'

control 'V-38676' do
  impact 0.1
  title 'The xorg-x11-server-common (X Windows) package must not be installed, unless required.'
  desc '
Unnecessary packages should not be installed to decrease the attack surface of the system.
'
  tag 'stig','V-38676'
  tag severity: 'low'
  tag checkid: 'C-46236r1_chk'
  tag fixid: 'F-43625r1_fix'
  tag version: 'RHEL-06-000291'
  tag ruleid: 'SV-50477r2_rule'
  tag fixtext: '
Removing all packages which constitute the X Window System ensures users or malicious software cannot start X. To do so, run the following command: 

# yum groupremove "X Window System"
'
  tag checktext: '
To ensure the X Windows package group is removed, run the following command: 

$ rpm -qi xorg-x11-server-common

The output should be: 

package xorg-x11-server-common is not installed


If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
