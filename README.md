# psfisolate

Sample isolation tool for PSF1 files.

## Usage

Drop a file onto the program, or run it via command line. To show help info, execute it without additional arguments.

## FAQ

#### Q: Most/all of the output files are silent/won't open?
**A:** There are numerous possible reasons for this. If only some of the files are silent, the game may use shared sound banks, where the song only uses some of the samples (please understand that psfisolate has no knowledge of which samples are actually used). If all files are silent, or won't even open, the scanning algorithm may have found a false positive sample in the executable data and corrupted the sound driver as a result -- try tweaking the options.

## Known issues

#### False positives
Even with larger regions of data, false positive samples may still be found. Try tweaking the scanning options if you have this issue. If program data (CPU instructions, ASCII strings, etc.) could somehow be detected and excluded from the search space, this could help a lot. But this may be difficult to implement properly.

#### Unicode paths
It currently does not support Unicode paths. Any path or string argument supplied must consist of ASCII characters only.
