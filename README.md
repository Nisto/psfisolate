# psfisolate

Sample isolation tool for PSF1 files.

## Usage

Drop a file onto the program, or run it via command line. To show help info, execute it without additional arguments.

## Known issues

#### False positives
Even with larger regions of data, false positive samples may still be found. Try tweaking the scanning options if you have this issue. If program data (CPU instructions, ASCII strings, etc.) could somehow be detected and excluded from the search space, this could help a lot. But this may be difficult to implement properly.

#### Unicode paths
It currently does not support Unicode paths. Any path or string argument supplied must consist of ASCII characters only.
