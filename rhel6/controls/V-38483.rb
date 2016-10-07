# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38483 - The system package management tool must cryptographically verify the authenticity of system software packages during installation.'

control 'V-38483' do
  impact 0.5
  title 'The system package management tool must cryptographically verify the authenticity of system software packages during installation.'
  desc '
Ensuring the validity of packages\' cryptographic signatures prior to installation ensures the provenance of the software and protects against malicious tampering.
'
  tag 'stig','V-38483'
  tag severity: 'medium'
  tag checkid: 'C-46039r1_chk'
  tag fixid: 'F-43429r1_fix'
  tag version: 'RHEL-06-000013'
  tag ruleid: 'SV-50283r1_rule'
  tag fixtext: '
The "gpgcheck" option should be used to ensure checking of an RPM package\'s signature always occurs prior to its installation. To configure yum to check package signatures before installing them, ensure the following line appears in "/etc/yum.conf" in the "[main]" section: 

gpgcheck=1
'
  tag checktext: '
To determine whether "yum" is configured to use "gpgcheck", inspect "/etc/yum.conf" and ensure the following appears in the "[main]" section: 

gpgcheck=1

A value of "1" indicates that "gpgcheck" is enabled. Absence of a "gpgcheck" line or a setting of "0" indicates that it is disabled. 
If GPG checking is not enabled, this is a finding.

If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
