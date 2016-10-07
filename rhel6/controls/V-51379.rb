# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-51379 - All device files must be monitored by the system Linux Security Module.'

control 'V-51379' do
  impact 0.1
  title 'All device files must be monitored by the system Linux Security Module.'
  desc '
If a device file carries the SELinux type "unlabeled_t", then SELinux cannot properly restrict access to the device file. 
'
  tag 'stig','V-51379'
  tag severity: 'low'
  tag checkid: 'C-53719r1_chk'
  tag fixid: 'F-56179r1_fix'
  tag version: 'RHEL-06-000025'
  tag ruleid: 'SV-65589r1_rule'
  tag fixtext: '
Device files, which are used for communication with important system resources, should be labeled with proper SELinux types. If any device files carry the SELinux type "unlabeled_t", investigate the cause and correct the file\'s context. 
'
  tag checktext: '
To check for unlabeled device files, run the following command:

# ls -RZ /dev | grep unlabeled_t

It should produce no output in a well-configured system. 

If there is output, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
