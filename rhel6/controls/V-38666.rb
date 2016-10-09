# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38666 - The system must use and update a DoD-approved virus scan program.'

control 'V-38666' do
  impact 1.0
  title 'The system must use and update a DoD-approved virus scan program.'
  desc '
Virus scanning software can be used to detect if a system has been compromised by computer viruses, as well as to limit their spread to other systems.
'
  tag 'stig','V-38666'
  tag severity: 'high'
  tag checkid: 'C-46226r2_chk'
  tag fixid: 'F-43615r2_fix'
  tag version: 'RHEL-06-000284'
  tag ruleid: 'SV-50467r2_rule'
  tag fixtext: '
Install virus scanning software, which uses signatures to search for the presence of viruses on the filesystem.

The McAfee VirusScan Enterprise for Linux virus scanning tool is provided for DoD systems. Ensure virus definition files are no older than 7 days, or their last release.

Configure the virus scanning software to perform scans dynamically on all accessed files. If this is not possible, configure the system to scan all altered files on the system on a daily basis. If the system processes inbound SMTP mail, configure the virus scanner to scan all received mail.
'
  tag checktext: '
Inspect the system for a cron job or system service which executes a virus scanning tool regularly.
To verify the McAfee VSEL system service is operational, run the following command:

# /etc/init.d/nails status

To check on the age of uvscan virus definition files, run the following command:

# cd /opt/NAI/LinuxShield/engine/dat
# ls -la avvscan.dat avvnames.dat avvclean.dat

If virus scanning software does not run continuously, or at least daily, or has signatures that are out of date, this is a finding.
'

# START_DESCRIBE V-38666
  tag 'virus','untestable'
  # untestable... can't know about all virus scanners
# END_DESCRIBE V-38666

end
