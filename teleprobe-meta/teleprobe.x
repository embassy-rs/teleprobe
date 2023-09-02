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
}