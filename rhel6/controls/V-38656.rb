# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38656 - The system must use SMB client signing for connecting to samba servers using smbclient.'

control 'V-38656' do
  impact 0.1
  title 'The system must use SMB client signing for connecting to samba servers using smbclient.'
  desc '
Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.
'
  tag 'stig','V-38656'
  tag severity: 'low'
  tag checkid: 'C-46217r1_chk'
  tag fixid: 'F-43606r1_fix'
  tag version: 'RHEL-06-000272'
  tag ruleid: 'SV-50457r1_rule'
  tag fixtext: '
To require samba clients running "smbclient" to use packet signing, add the following to the "[global]" section of the Samba configuration file in "/etc/samba/smb.conf": 

client signing = mandatory

Requiring samba clients such as "smbclient" to use packet signing ensures they can only communicate with servers that support packet signing.
'
  tag checktext: '
To verify that Samba clients running smbclient must use packet signing, run the following command: 

# grep signing /etc/samba/smb.conf

The output should show: 

client signing = mandatory


If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
