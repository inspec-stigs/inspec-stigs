# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38476 - Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.'

control 'V-38476' do
  impact 1.0
  title 'Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.'
  desc '
The Red Hat GPG keys are necessary to cryptographically verify packages are from Red Hat. 
'
  tag 'stig','V-38476'
  tag severity: 'high'
  tag checkid: 'C-46031r3_chk'
  tag fixid: 'F-43421r3_fix'
  tag version: 'RHEL-06-000008'
  tag ruleid: 'SV-50276r3_rule'
  tag fixtext: '
To ensure the system can cryptographically verify base software packages come from Red Hat (and to connect to the Red Hat Network to receive them), the Red Hat GPG keys must be installed properly. To install the Red Hat GPG keys, run:

# rhn_register

If the system is not connected to the Internet or an RHN Satellite, then install the Red Hat GPG keys from trusted media such as the Red Hat installation CD-ROM or DVD. Assuming the disc is mounted in "/media/cdrom", use the following command as the root user to import them into the keyring:

# rpm --import /media/cdrom/RPM-GPG-KEY
'
  tag checktext: '
To ensure that the GPG keys are installed, run:

$ rpm -q gpg-pubkey

The command should return the strings below:

gpg-pubkey-fd431d51-4ae0493b
gpg-pubkey-2fa658e0-45700c69

If the Red Hat GPG Keys are not installed, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
