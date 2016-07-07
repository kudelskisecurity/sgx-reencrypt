
X = reencrypt

.PHONY: clean format

clean:  
	        rm -rf Debug/  Prerelease/ 
	        rm -f $(X).sdf

format:
		clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4}" \
                -i reencrypt/**.c reencrypt/**.h test-app/**.c test-app/**.h

