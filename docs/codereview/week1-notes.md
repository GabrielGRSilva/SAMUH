## Verified requirements

Go 1.26.7 for this version 1.0.

## Verified Commands and Preparation
**Command**: go mod download

**Summary**: Installs the dependencies determined in go.mod.

-----------------

**Command**: go mod tidy

**Summary**: Verifies the use of dependencies through the project, removes unused modules and removes the comment //indirect if they are directly called (which happened for Cobra).

-----------------

**Command**: go vet ./...

**Summary**: Scans the project and all its packages for errors that wouldn't be picked by the go build (compile) process.

-----------------
**Command**: go build -o samuh.exe .

**Summary**: 
- Compiles the project;
- Stops if there are any errors;
- If everything is ok, builds the samuh.exe executable.

-----------------

**Command**: ./samuh.exe scan testdata --format json

**Summary**: 
- Verifies if testdata is a valid directory;
- Validate the files which will be covered during the scan;
- Scan the files looking for vulnerabilities;
- Output the scan results following the designed format (and, in this case, json);
- It starts from main.go, moving to the cmd.Execute() in root.go (which gives control to the Cobra Framework) and finally moves to scan.go (from root.go Execute() ) to proceed with the scan itself and the internal rules and processes.


