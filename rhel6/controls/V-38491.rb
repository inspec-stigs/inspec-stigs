# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38491 - There must be no .rhosts or hosts.equiv files on the system.'

control 'V-38491' do
  impact 1.0
  title 'There must be no .rhosts or hosts.equiv files on the system.'
  desc '
Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system.
'
  tag 'stig','V-38491'
  tag severity: 'high'
  tag checkid: 'C-46048r1_chk'
  tag fixid: 'F-43438r1_fix'
  tag version: 'RHEL-06-000019'
  tag ruleid: 'SV-50292r1_rule'
  tag fixtext: '
The files "/etc/hosts.equiv" and "~/.rhosts" (in each user\'s home directory) list remote hosts and users that are trusted by the local system when using the rshd daemon. To remove these files, run the following command to delete them from any location. 

# rm /etc/hosts.equiv



$ rm ~/.rhosts
'
  tag checktext: '
The existence of the file "/etc/hosts.equiv" or a file named ".rhosts" inside a user home directory indicates the presence of an Rsh trust relationship. 
If these files exist, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
