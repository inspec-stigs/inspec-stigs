# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38659 - The operating system must employ cryptographic mechanisms to protect information in storage.'

control 'V-38659' do
  impact 0.1
  title 'The operating system must employ cryptographic mechanisms to protect information in storage.'
  desc '
The risk of a system\'s physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost.
'
  tag 'stig','V-38659'
  tag severity: 'low'
  tag checkid: 'C-46220r1_chk'
  tag fixid: 'F-43609r1_fix'
  tag version: 'RHEL-06-000275'
  tag ruleid: 'SV-50460r1_rule'
  tag fixtext: '
Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time.

For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots.

For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition:

part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation.

Detailed information on encrypting partitions using LUKS can be found on the Red Had Documentation web site:
https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
'
  tag checktext: '
Determine if encryption must be used to protect data on the system.
If encryption must be used and is not employed, this is a finding.
'

# START_DESCRIBE V-38659
  tag 'untestable','encryption'
  # not testable, as do not know req for encryption
# END_DESCRIBE V-38659

end
