# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38449 - The /etc/gshadow file must have mode 0000.'

control 'V-38449' do
  impact 0.5
  title 'The /etc/gshadow file must have mode 0000.'
  desc '
The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security.
'
  tag 'stig','V-38449'
  tag severity: 'medium'
  tag checkid: 'C-46004r1_chk'
  tag fixid: 'F-43394r1_fix'
  tag version: 'RHEL-06-000038'
  tag ruleid: 'SV-50249r1_rule'
  tag fixtext: '
To properly set the permissions of "/etc/gshadow", run the command: 

# chmod 0000 /etc/gshadow
'
  tag checktext: '
To check the permissions of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following permissions: "----------" 
If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
