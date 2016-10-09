# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38657 - The system must use SMB client signing for connecting to samba servers using mount.cifs.'

control 'V-38657' do
  impact 0.1
  title 'The system must use SMB client signing for connecting to samba servers using mount.cifs.'
  desc '
Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.
'
  tag 'stig','V-38657'
  tag severity: 'low'
  tag checkid: 'C-46218r4_chk'
  tag fixid: 'F-43607r1_fix'
  tag version: 'RHEL-06-000273'
  tag ruleid: 'SV-50458r2_rule'
  tag fixtext: '
Require packet signing of clients who mount Samba shares using the "mount.cifs" program (e.g., those who specify shares in "/etc/fstab"). To do so, ensure signing options (either "sec=krb5i" or "sec=ntlmv2i") are used.

See the "mount.cifs(8)" man page for more information. A Samba client should only communicate with servers who can support SMB packet signing.
'
  tag checktext: '
If Samba is not in use, this is not applicable.

To verify that Samba clients using mount.cifs must use packet signing, run the following command:

# grep sec /etc/fstab /etc/mtab

The output should show either "krb5i" or "ntlmv2i" in use.
If it does not, this is a finding.
'

# START_DESCRIBE V-38657
  tag 'samba','smbclient','fstab','mtab'
  only_if { command('mount.cifs').exist? }
  describe command('grep sec /etc/fstab /etc/mtab') do
    its('stdout') { should eq '' }
  end
# END_DESCRIBE V-38657

end
