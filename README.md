# Process Snapshot Tool

A command-line tool that takes a process snapshot and provides detailed data, including thread details, handle information, virtual address space, and KUSER shared data.  
The tool is ment mostly to help capture data for use in diff anlysis in 2 states of time of the same process. It does not capture arbitrary memory content.

The vast majority of data is done using snapshots from the following API:
https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/  
There are no write operations done on the cloned pages so no CoW introduced on the captured process (AFIK).

## Features

- **Thread Information**: Display detailed thread information within the process.
- **Handle Information**: List handles opened by the process.
- **Virtual Address (VA) Space**: Show the layout and details of the process's virtual address space.
- **Auxiliary Pages**: Enumerate auxiliary pages captured in the snapshot.
- **KUSER_SHARED_DATA**: Read and display the `KUSER_SHARED_DATA` structure for the process.

## Usage

To use the tool, run it from the command line with the target process's PID and the desired options:


### Options

- `+thread`: Include thread information in the output.
- `+handle`: Include handle information in the output.
- `+va`: Include virtual address space information in the output.
- `+aux`: Include auxiliary pages information in the output.
- `+kusd`: Include `KUSER_SHARED_DATA` information in the output.

### Example

To capture and display basic + handle information for a process with PID 1347:  
```
./procsnap.exe 1347 +thread +handle +kusd >> snapshot.txt
```
To capture and display all information for a process with PID 1347:
```
./procsnap.exe 1347 +all >> snapshot.txt
./procsnap.exe 1347 +thread +handle +va +aux +kusd >> snapshot.txt
```

To actually do the analysis use a proper diffchecker with decent UI

![image](https://github.com/Argentix03/ProcSnap/assets/39255806/79bdcaae-c38b-4fa0-a1ed-4c4793fa9a6d)
![image](https://github.com/Argentix03/ProcSnap/assets/39255806/d0c1217b-8516-4f21-af0d-5b04aef7d705)



