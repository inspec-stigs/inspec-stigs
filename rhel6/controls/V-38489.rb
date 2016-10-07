# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38489 - A file integrity tool must be installed.'

control 'V-38489' do
  impact 0.5
  title 'A file integrity tool must be installed.'
  desc '
The AIDE package must be installed if it is to be available for integrity checking.
'
  tag 'stig','V-38489'
  tag severity: 'medium'
  tag checkid: 'C-46046r1_chk'
  tag fixid: 'F-43436r1_fix'
  tag version: 'RHEL-06-000016'
  tag ruleid: 'SV-50290r1_rule'
  tag fixtext: '
Install the AIDE package with the command: 

# yum install aide
'
  tag checktext: '
If another file integrity tool is installed, this is not a finding.

Run the following command to determine if the "aide" package is installed: 

# rpm -q aide


If the package is not installed, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
