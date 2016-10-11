package Mail::SpamAssassin::Plugin::OLEMacro;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use IO::String;

use strict;
use warnings;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

our $VERSION = '0.3';

my $marker1 = "\xd0\xcf\x11\xe0";
my $marker2 = "\x00\x41\x74\x74\x72\x69\x62\x75\x74\x00";

# https://blogs.msdn.microsoft.com/vsofficedeveloper/2008/05/08/office-2007-file-format-mime-types-for-http-content-streaming-2/
# https://technet.microsoft.com/en-us/library/ee309278(office.12).aspx
my $macrotypes = qr/(?:docm|dotm|potm|ppst|pptm|xlsb|xlsm|xltm)$/;
my $exts = qr/(?:doc|dot|pot|pps|ppt|xls|xlt)$/;
my $skip_ctype = qr/^(?:(audio|image|text)\/|application\/(?:pdf))/;
my $skip_exts = qr/\.(?:csv|docx|dotx|gif|html?|jpe?g|pdf|png|potx|pptx|txt|xlsx|xml)$/;

my $max_mime = 5;
my $max_zip = 5;
my $zip_num_of_bytes = 512000;

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_olemacro");

  return $self;
}

sub dbg {
  Mail::SpamAssassin::Plugin::dbg ("OLEMacro: @_");
}

sub check_olemacro {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_exists};

  return $pms->{olemacro_exists};
}

sub _check_attachments {

  my ($self,$pms,$body,$name) = @_;

  my $mimec = 0;

  $pms->{olemacro_exists} = 0;

  foreach my $part ($pms->{msg}->find_parts(qr/./, 1)) {

    my $ctt = $part->get_header('content-type');
    next unless defined $ctt;
    my ($ctype) =
      Mail::SpamAssassin::Util::parse_content_type($ctt);
    $ctt = _decode_part_header($part, lc($ctt || ''));

    my $name='';
    if($ctt =~ m/name\s*=\s*"?([^";]*)"?/is){
      $name=$1;
      # lets be sure and remove any whitespace from the end
      $name =~ s/\s+$//;
    }

    $name = lc $name;
    next if $name eq '';
    next if ($name =~ $skip_exts);

    my $cte = lc($part->get_header('content-transfer-encoding') || '');
    next unless ($cte =~ /^(?:base64)$/);

    $ctype = lc $ctype;
    next if ($ctype =~ $skip_ctype);

    dbg("Found attachment with name $name of type $ctype ");

    # if name is macrotype - return true
    if ($name =~ $macrotypes) {
      $pms->{olemacro_exists} = 1;
      return 1;
    }

    my $data = undef;

    # if name is ext type - check and return true if needed
    if ($name =~ $exts) {
      $data = $part->decode() unless defined $data;
      if (_check_markers($data)) {
        $pms->{olemacro_exists} = 1;
        return 1;
      }
    }

    # check for zip
    $data = $part->decode(6) unless defined $data;

    if (_is_zip_file($name, $data)) {
      dbg("$name is a zip file");
      $data = $part->decode() if length $data == 6;
      if (_check_zip($data)) {
        $pms->{olemacro_exists} = 1;
        return 1;
      }
    }

    $mimec += 1 if defined $data;
    last if $mimec > $max_mime;

  }
  return 0;
}

sub _check_zip {
  my ($data) = @_;

  # open our archive from raw datas
  my $SH = IO::String->new($data);

  Archive::Zip::setErrorHandler( \&_zip_error_handler );
  my $zip = Archive::Zip->new();
  if($zip->readFromFileHandle( $SH ) != AZ_OK){
    dbg("cannot read zipfile");
    # as we cannot read it its not a zip (or too big/corrupted)
    # so skip processing.
    return 0;
  }

  my $filec = 0;

  my @members = $zip->members();

  # Look for a member named [Content_Types].xml and do checks

  if (my $ctypesxml = $zip->memberNamed('[Content_Types].xml')) {
    dbg('Found [Content_Types].xml file');
    my ( $data, $status ) = $ctypesxml->contents();
    return 0 unless $status == AZ_OK;
    if (_check_ctype_xml($data)) {
      return 1;
    } else {
      return 0;
    }
  }

  # foreach zip member
  # - skip if in skip exts
  # - return 1 if in macro types
  # - check for marker if doc type
  # - check if a zip
  foreach my $member (@members){
    my $mname = lc $member->fileName();
    next if $mname =~ $skip_exts;
    return 1 if $mname =~ $macrotypes;

    my $data = undef;
    my $status = undef;

    if ($mname =~ $exts) {
      ( $data, $status ) = $member->contents() unless defined $data;
      next unless $status == AZ_OK;
      if (_check_markers($data)) {
        return 1;
      }
    }

    ( $data, $status ) = $member->contents() unless defined $data;
    next unless $status == AZ_OK;

    if (_is_zip_file($mname, $data)) {
      dbg("$mname is a zip file");
      if (_check_zip($data)) {
        return 1;
      }
    }

    $filec+=1 if defined $data;
    last if $filec > $max_zip;
  }
}

sub _is_zip_file {
  my ($name, $data) = @_;
  if (index($data, 'PK') == 0) {
    return 1;
  } else {
    return($name =~ /(?:zip)$/);    
  }
}

sub _check_markers {
  my ($data) = @_;
  if (index($data, $marker1) == 0 && index($data, $marker2) > -1) {
    dbg('Marker found');
    return 1;
  }
}

sub _check_ctype_xml {
  my ($data) = @_;

  # http://download.microsoft.com/download/D/3/3/D334A189-E51B-47FF-B0E8-C0479AFB0E3C/[MS-OFFMACRO].pdf
  if ($data =~ /ContentType=["']application\/vnd\.ms-office\.vbaProject["']/i){
    dbg('Found VBA ref');
    return 1;
  }
  if ($data =~ /macroEnabled/i) {
    dbg('Found Macro Ref');
    return 1;
  }
  if ($data =~ /application\/vnd\.ms-excel\.(?:intl)?macrosheet/i) {
    dbg('Excel macrosheet found');
    return 1;
  }
}

sub _zip_error_handler {

}

sub _decode_part_header {
  my($part, $header_field_body) = @_;

  return '' unless defined $header_field_body && $header_field_body ne '';

  # deal with folding and cream the newlines and such
  $header_field_body =~ s/\n[ \t]+/\n /g;
  $header_field_body =~ s/\015?\012//gs;

  local($1,$2,$3);

  # Multiple encoded sections must ignore the interim whitespace.
  # To avoid possible FPs with (\s+(?==\?))?, look for the whole RE
  # separated by whitespace.
  1 while $header_field_body =~
            s{ ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) \s+
               ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) }
             {$1$2}xsg;

  # transcode properly encoded RFC 2047 substrings into UTF-8 octets,
  # leave everything else unchanged as it is supposed to be UTF-8 (RFC 6532)
  # or plain US-ASCII
  $header_field_body =~
    s{ (?: = \? ([A-Za-z0-9_-]+) \? ([bqBQ]) \? ([^?]*) \? = ) }
     { $part->__decode_header($1, uc($2), $3) }xsge;

  return $header_field_body;
}

1;
