SECTIONS
{
  .teleprobe.target (INFO) :
  {
    KEEP(*(.teleprobe.target));
  }
  .teleprobe.timeout (INFO) :
  {
    KEEP(*(.teleprobe.timeout));
  }
  .teleprobe.export (INFO) :
  {
    KEEP(*(.teleprobe.export));
  }
}
