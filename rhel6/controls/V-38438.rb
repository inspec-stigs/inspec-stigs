# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38438 - Auditing must be enabled at boot by setting a kernel parameter.'

control 'V-38438' do
  impact 0.1
  title 'Auditing must be enabled at boot by setting a kernel parameter.'
  desc '
Each process on the system carries an "auditable" flag which indicates whether its activities can be audited. Although "auditd" takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot.
'
  tag 'stig','V-38438'
  tag severity: 'low'
  tag checkid: 'C-45992r2_chk'
  tag fixid: 'F-43382r2_fix'
  tag version: 'RHEL-06-000525'
  tag ruleid: 'SV-50238r2_rule'
  tag fixtext: '
To ensure all processes can be audited, even those which start prior to the audit daemon, add the argument "audit=1" to the kernel line in "/etc/grub.conf", in the manner below:

kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1

UEFI systems may prepend "/boot" to the "/vmlinuz-version" argument. 
'
  tag checktext: '
Inspect the kernel boot arguments (which follow the word "kernel") in "/etc/grub.conf". If they include "audit=1", then auditing is enabled at boot time. 

If auditing is not enabled at boot time, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
