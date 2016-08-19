#!/usr/bin/perl

# Dovecot mdbox parser
# (C) 2016 Ben Duncan, Atmail Pty Ltd
# Apache 2.0 License

use MIME::Base64;
use Getopt::Long;
use Amazon::S3::Thin;
use Data::Dumper;
use File::Temp qw/ tempfile tempdir /;
use Redis::Client;

# TODO: Remove globals, make a module
$debug = 0;
$file;
$help;
$out;
$dir;
$eml;
$attachdir;
$s3secretKey;
$s3accessKey;
$s3host;
$s3bucket;
$loadattachs3;
$s3client;
$redishost;
$redisclient;
$redisreloadcache;

use constant DBOX_VERSION => 2;
use constant DBOX_MAGIC_PRE => "\001\002";
use constant DBOX_MAGIC_POST => "\n\001\003\n";
use Switch;

# Options via the CLI
GetOptions(	"debug"		=> \$debug,
			"file=s"	=> \$file,
			"help"		=> \$help,
			"out=s"		=> \$out,
			"dir=s"		=> \$dir,
			"eml"		=>	\$eml,
			"attachdir=s"	=> \$attachdir,
			"s3-host=s"	=> \$s3host,
			"s3-bucket=s"	=> \$s3bucket,
			"s3-secret-key=s"	=> \$s3secretKey,
			"s3-access-key=s"	=> \$s3accessKey,
			"loadattachs3"		=> \$loadattachs3,
			"redis-host=s"		=> \$redishost,
			"redis-reloadcache"	=> \$redisreloadcache
			) or die("Undefined args");

# Simple error checking for the correct arguments
if( (!$file && !$dir) || $help || !$attachdir)	{
	die usage();
}

if(!-d $attachdir)	{
	die "$attachdir is not a directory: Can not open attachments\n";
}

if(!-d $dir && $dir)	{
	die "$dir is not a directory: Can not read messages\n";
}

if(!-f $file && $file)	{
	die "$file is not a valid path: Can not read message\n";
}

if( $loadattachs3 && (!$s3host || !$s3bucket || !$s3secretKey || !$s3accessKey) ) {
	die "--loadattachs3 defined, but missing full S3 credentials\n";
}

if( $s3host && $s3bucket && $s3secretKey && $s3accessKey )	{
# Connect to S3
		$s3client = Amazon::S3::Thin->new(
		    {   aws_access_key_id     => $s3accessKey,
		        aws_secret_access_key => $s3secretKey,
		    }
		);
}


if($redishost)	{

	$redisclient = Redis::Client->new( host => $redishost, port => 6379 );

}



# If a directory is specified, scan the path for all mdbox messages
if(-d $dir && $dir)	{
	
	@files = findMessages($dir);

	foreach(@files)	{
		parseMdbox($_);
	}

# Otherwise, use the file specified on the CLI
} else {
	parseMdbox($file);
}


exit;

sub parseMdbox	{
	$file = shift(@_);

open(F, $file) || die "Cannot open " . $file . " : $!\n";

$i = 0;

#/* The file begins with a header followed by zero or more messages:
#
#   <dbox message header>
#   <LF>
#   <message body>
#   <metadata>
#
#   Metadata block begins with DBOX_MAGIC_POST, followed by zero or more lines
#   in format <key character><value><LF>. The block ends with an empty line.
#   Unknown metadata should be ignored, but preserved when copying.
#
#   There should be no duplicates for the current metadata, but future
#   extensions may need them so they should be preserved.
#*/

my %dboxHeader;
my %dboxMetadata;

while(<F>)	{
	$line = $_;
	# If opening a raw mdbox, parse the first header
	# Sample header (values in hex)
	# VERSION DBOX_HEADER_MSG_HEADER_SIZE DBOX_HEADER_CREATE_STAMP
	# 2 M1e C57a4900f

	if($line =~ /^${\(DBOX_VERSION)} M(\w+) C(\w+)/ && $i == 0)	{

		$dboxHeader{"DBOX_HEADER_MSG_HEADER_SIZE"} = hex($1);
		$dboxHeader{"DBOX_HEADER_CREATE_STAMP"} = hex($2);

		foreach(keys %dboxHeader)	{
			printDebug("$_ => " . $dboxHeader{$_} . "\n");
		}

		next;
	}

	$file .= $line;
	$i++;
}

# Messages are split between ^A^BN Unique-ID
@messages = split(/${\(DBOX_MAGIC_PRE)}N(\s+\w+)\n/, $file, -1);

foreach my $mail (@messages)	{

	# Messages contain a footer with the MIME parts location on disk, and message offsets
	$mail =~ m/^\cA\cC(.*)$/sm;

	$info = $1;

	# Dovecot mdbox format ($info):

	# X1442 2742784 94/b2/01f34a9def84372a440d7a103a159ac6c9fd752b
	#  2744378 27423 27/c8/a1dccc34d0aaa40e413b449a18810f600b4ae77b
	#
	# So the format is:
	#
	# "X" 1*(<offset> <byte count> <link path>)
	#
	# So when reading a dbox message body, it's read as:
	#
	# offset=0: <first 1442 bytes from dbox body>
	# offset=1442: <next 2742784 bytes from external file>
	# offset=2744226: <next 152 bytes from dbox body>
	# offset=2744378: <next 27423 bytes from external file>
	# offset=2744378 27423: <the rest from dbox body>


	# Remove the footer from the raw message, the client does not require it.
	$mail =~ s/$info//g;
	$mail =~ s/\cA\cC//g;
	
	printDebug("Mdbox info => $info => length => " . length($info) . "\n");

	if($info)	{

		printDebug("\t$info\n");

		@fields = split(/\n/, $info);

		$m = 1;

		foreach my $field (@fields)	{
			printDebug("$m => \t\t$field\n");

			$field =~ /(\w)(.*)$/;

			my $header = $1;
			my $value = $2;

			$dboxMetadata{$header} = $value;

			# Loop through the meta data
			switch($header)	{

				case "G"	{ $dboxMetadata{"DBOX_METADATA_GUID"} = $value }
				case "P"	{ $dboxMetadata{"DBOX_METADATA_POP3_UIDL"} = hex($value) }
				case "O"	{ $dboxMetadata{"DBOX_METADATA_POP3_ORDER"} = hex($value) }
				case "R"	{ $dboxMetadata{"DBOX_METADATA_RECEIVED_TIME"} = hex($value) }
				case "Z"	{ $dboxMetadata{"DBOX_METADATA_PHYSICAL_SIZE"} = hex($value) }
				case "V"	{ $dboxMetadata{"DBOX_METADATA_VIRTUAL_SIZE"} = hex($value) }
				case "X"	{ $dboxMetadata{"DBOX_METADATA_EXT_REF"} = hex($value) }
				case "B"	{ $dboxMetadata{"DBOX_METADATA_ORIG_MAILBOX"} = $value }

			}

			$m++;
		}

		foreach(sort keys %dboxMetadata)	{
			printDebug("$_ => " . $dboxMetadata{$_} . "\n");
		}

		printDebug("Attachments => $fields[6]\n");

		@attachments = split(/ /sm, $fields[6]);
		$total = $#attachments;
		$total++;

		printDebug("total => $total\n");

		$attachment_parts = $total / 4;

		printDebug("attachment_parts => $attachment_parts\n");

		# Hash containing all attachment types, Base64 encoded.
		my %attachHash;
		my @s3upload;

		my $b = 0;
		foreach my $attachment (@attachments)	{

			$attachment =~ s/^X//g;

			printDebug("Attachment part $b => $attachment\n");

# Attachment filenames in Dovecot are prefixed by the first 4 characters of the SSHA1sum, e.g
#[root@centos6dev ~]# sha1sum /tmp/attach/ff/58/ff580c6b29888313c23577e8acd811a28d499588-3b45980767faab57ef4e0000adf06059
#ff580c6b29888313c23577e8acd811a28d499588  /tmp/attach/ff/58/ff580c6b29888313c23577e8acd811a28d499588-3b45980767faab57ef4e0000adf06059

			if(-e "$attachdir/$attachment")	{

				my $data;
				my $pathname;

				if($loadattachs3) {

				$data = "";

				# First, check redis, if we have a local copy, don't query the network

				if($redishost && !$redisreloadcache)	{

					printSTDERR("Checking redis for key $attachdir/$attachment:\t\t");
					# work with strings
					$data = $redisclient->get("$attachdir/$attachment" );

					if($data)	{
						printSTDERR("HIT\n");
					} else {
						printSTDERR("MISS\n");
					}

				}

				if(!$data)	{

					 my $response = $s3client->get_object($s3bucket, "$attachdir/$attachment");
					 
					 #($fh, $pathname) = tempfile();
					 printSTDERR("Fetching S3 attachment, key => $attachdir/$attachment\n");

					 #print $fh $response->content;
					 #close($fh);
					 $data = $response->content;

					 if($redishost)	{
					 	printSTDERR("Adding $attachdir/$attachment key to redis cache:\t\t");

					 	$redisclient->del("$attachdir/$attachment");
					 	$redisclient->set("$attachdir/$attachment", $data);

					 	printSTDERR("OK\n");

					 }


				}


				} else {

					$pathname = "$attachdir/$attachment";
					push(@s3upload, "$attachdir/$attachment");

					printSTDERR("Loading $pathname from disk: ");
					open(F2, $pathname) || die "Cannot open $pathname: $!\n";
					binmode(F2);

					$data = "";
					while(<F2>)	{
						$data .= $_;
					}
					close(F2);

					printSTDERR(" File length => " . length($data) . "\n");

				}

				# Perl's base64 wraps to 76 lines, we need 72 to match dovecot and the offsets
				# TODO: Possibe to fix encode_base64? Line wrap does not seem to be an argument
				# TODO: After research 76 chars is correct!
				#$data = `base64 $pathname`;
				$data = encode_base64($data);
				chomp($data);

				printDebug("\tData length => " . length($data) . "\n");

				$offset = $b - 3;
				printDebug("Offset > $offset " . $attachments[$offset] . "\n");

				# Save the attachment in the hash, by the byte offset. Used when priting the entire mail.
				$attachHash{ $attachments[$offset] } = $data;

			}

			$b++;
		}

		# Upload attachments to S3 if specified, but skip if loadattachs3 defined on CLI ( fetch from S3 vs upload them )
		if($s3host && $s3bucket && $s3secretKey && $s3accessKey && $#s3upload >= 0 && !$loadattachs3)	{

			print STDERR "Uploading attachments to S3\n";

			# TODO: Check if the local checksum == server, if so do not upload the same thing
			foreach(@s3upload)	{
				my $file = $_;

				my $attachData;

				printSTDERR("Uploading $file:\t\t");

				open(F3, $file) || die "Cannot open $file: $!\n";
				binmode(F3);
				while(<F3>)	{
					$attachData .= $_;
				}
				close(F3);

				$response = $s3client->put_object($s3bucket, $file, $attachData);

				if($response->is_success)	{
					printSTDERR("OK\n");
				} else	{
					printSTDERR("FAILED (" . $response->content . ")\n");
				}

			}

		}

		for (1 .. $attachment_parts)	{
			$i = $_;
			$index = $i * $attachment_parts -1;
			printDebug("\t$i => $index => Attachment path => $attachments[$index]\n");
		}


	# Split all characters into an array, unpack vs split
	my @bytes = unpack('C*', $mail);
	#my @bytes = split('', $mail);

	my $index = 0;

	if(!$debug)	{

		my $fh;

		if($out)	{

			my $folder = "$out/" . $dboxMetadata{"DBOX_METADATA_ORIG_MAILBOX"};


			# Create the output direcotry and folder to export
			mkdir($out) if(!-d $out);
			mkdir($folder) if(!-d $folder);

			my $file = $folder . "/" . $dboxMetadata{"DBOX_METADATA_GUID"};

			$file = $file . ".eml" if($eml);

			my $succ = open( $fh , '>', $file ) || die "Cannot write to $file: $!\n";

			printSTDERR("Outputing message to $file\n");

			$fh = *STDOUT unless $succ;

		} else {
			$fh = *STDOUT;

		}

		foreach $byte (@bytes)	{
			
			$index++;

			#print $byte;
			print $fh pack('C*', $byte);

			# Are we are the offset position? Substitute the MIME part
			if( $attachHash{$index} )	{
				print $fh $attachHash{$index};

				# Bump the index from current offset + attachment size
				$index = $index + length($attachHash{$index});
			}

		}


	}

	}

}

}


####### Private methods

sub findMessages {
    my $path    = shift;

    opendir (DIR, $path)
        or die "Unable to open $path: $!";

    my @files =
        map { $path . '/' . $_ }
        grep { !/^\.{1,2}$/ }
        readdir (DIR);

    # Rather than using a for() loop, we can just
    # return a directly filtered list.
    return
        grep { (/m\.\d+$/) && 
               (! -l $_) }
        map { -d $_ ? findMessages ($_) : $_ }
        @files;
}


sub printDebug()	{
	$message = shift(@_);

	return if(!$debug);

	print $message;
}

sub printSTDERR()	{
	$message = shift(@_);

	return if(!$out);

	print $message;
}

sub usage()	{
	print "mdbox-parse.pl: Version 1.0 \xF0\x9F\x8D\xBA\n\n";

	print "Usage:\n\n";
	print "perl mdbox-parser.pl " . " \e[90m--file\e[39m [/path/to/mdbox] \e[90m--dir\e[39m [/path/to/directory] \e[90m--out\e[39m [/path/to/export] \e[90m--eml\e[39m \e[90m--help\e[39m \e[90m--debug\e[39m\n\n";

	print "Requirements:\n\n";
	print "\e[90m--file\e[39m or \e[90m--dir\e[39m must be specified. Either to a raw mdbox file, or a directory containing a users mdbox pathname\n";
	print "\e[90m--attachdir\e[39m path to the Dovecot attachment directory, from the dovecot.conf\n\n";

	print "Options:\n\n";
	print "\e[90m--out\e[39m\t\t\tA pathname to a directory to export messages into. If not specfied will be printed to STDOUT\n";
	print "\e[90m--eml\e[39m\t\t\tAppend .eml to the filename on export, useful for viewing messages using third-party apps easier\n";
	print "\e[90m--debug\e[39m\e[39m\t\t\tShows message metadata without parsing to messages to disk or STDOUT\n";
	print "\e[90m--s3-host\e[39m\t\tHostname to the S3 instance to upload attachments\n";
	print "\e[90m--s3-secret-key\e[39m\t\tS3 secret key\n";
	print "\e[90m--s3-access-key\e[39m\t\tS3 access key\n";
	print "\e[90m--s3-bucket\e[39m\t\tName of the bucket to store attachments\n";
	print "\e[90m--loadattachs3\e[39m\t\tFetch attachments from S3, do not upload locally, rather load MIME parts from S3 storage\n";

	print "\e[90m--redisclient\e[39m\t\tOptionally, specify a Redis server to cache all requests received from S3\n";
	print "\e[90m--redis-reloadcache\e[39m\tForce all requests to S3, and reload the Redis cache with objects\n";

	print "\e[90m--help\e[39m\n\n";

	print "Example:\n\n";

	print "Before using this utility, you must have a Dovecot user with a valid mdbox mail-store.\n\n";

	print "\e[4mExample conversion:\e[24m\n";
	print "doveadm sync -D -u ben\@mydomain.com.au mdbox:/tmp/ben.mdbox\n";
	print "Convert an existing user from maildir to mdbox format and export to /tmp/ben.mdbox\n\n";

	print "\e[4mNext dependency, you must specify the attachment directory used by Dovecot:\e[24m\n";
	print "cat /path/to/dovecot.conf | grep mail_attachment_dir\n";
	print "mail_attachment_dir  = /tmp/attach\n\n";

	print "\e[4mExport mdbox to fully decoded MIME messages on disk, with attachments:\e[24m\n";

	print "perl mdbox-parse.pl --dir /tmp/ben.mdbox --attachdir /tmp/attach/ --out /tmp/mdbox-export/\n";
	print "Scan /tmp/ben.mdbox for all messages and output fully encoded messages with attachments to /tmp/mdbox-export/\n\n";

	print "\e[4mScan a specified mdbox file and output to STDOUT:\e[24m\n";
	print "perl mdbox-parse.pl --file /tmp/ben.mdbox/storage/m.9 --attachdir /tmp/attach/\n\n";

	print "\e[4mDecode mdbox attachments and upload to S3:\e[24m\n";
	print "perl mdbox-parse.pl --file /tmp/ben.mdbox/ --s3-secret-key SECRETKEY --s3-access-key ACCESSKEY --s3-host https://s3-us-west-2.amazonaws.com/ --s3-bucket MYBUCKET --attachdir /tmp/attach --loadattachs3 --out /tmp/mdbox.s3\n\n";

	print "\e[4mDecode mdbox attachments, query Redis for existing cache, else fetch from S3, store with EML extension:\e[24m\n";
	print "perl mdbox-parse.pl --file /tmp/ben.mdbox/ --s3-secret-key SECRETKEY --s3-access-key ACCESSKEY --s3-host https://s3-us-west-2.amazonaws.com/ --s3-bucket MYBUCKET --attachdir /tmp/attach --loadattachs3 --out /tmp/mdbox.s3 --redis-host 127.0.0.1 --eml\n\n";

	exit;
}

exit;
