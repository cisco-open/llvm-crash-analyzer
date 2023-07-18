#!bin/bash


FAST=8;
STOPPED=0;
FAIL_END=0;
RE_NUM=^[1-9]$

cmake -G "Ninja" -DLLVM_ENABLE_PROJECTS="clang;llvm-crash-analyzer;lldb;" \
	-B build \
	-DLLVM_ENABLE_LIBCXX=ON ./llvm -DLLDB_TEST_COMPILER=clang \
	-DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
	-DLLVM_ENABLE_ASSERTIONS=ON

if [ $? -eq 0 ]; then

	ninja -C build -j $FAST &> output.txt &
	BUILD_PID=$!;
	
	ch=0;
	ps $BUILD_PID > /dev/null;


	while [[ $? -eq 0 && $FAIL_END -eq 0 ]]; do
		str=$( tail output.txt -n 1);
		prevch=ch;
		ch=${str:0:1};
		if [ ch == '[' ]; then
			if [ prevch == '[' ]; then
				echo "";
			fi
			echo -ne "ECHO: ${str}\033[0K\r";
		else
			if [ prevch != '[' ]; then
				echo -ne "ECHO : ${str}\033[0K\r";
			else
				echo "ECHO: ${str}";
			fi
			
		fi
		
		sleep 0.25s;
		STOPPED=0;
		
		FREE_MEM=$( free -m | awk 'NR==2{printf "%d", $7*100/$2 }' );
		#echo $FREE_MEM
		if [ $FREE_MEM -le 5 ]; then
			pkill -P $BUILD_PID;
			kill $BUILD_PID;
			if [ $FAST -eq  1 ]; then
				echo -e "\n\nToo much mem consumption even on 1 processor\n\n"
				FAIL_END=1;
			else			
				echo -e "\n\nKilled build switched to slow mode!\n\n"
				while [ $FREE_MEM -lt 25 ]; do
					sleep 0.25s;
					FREE_MEM=$( free -m | awk 'NR==2{printf "%d", $7*100/$2 }' );
				done
				ninja -C build -j 1 &> output.txt &
				BUILD_PID=$!;
				(( FAST=FAST/2 ));
				STOPPED=1;
			fi

		
		else
			ch=${str:1:1};
			if [[ $FAST -ne 8 && $FREE_MEM -ge 50 && $ch =~ $RE_NUM ]]; then
				pkill -P $BUILD_PID;
				kill $BUILD_PID;
				(( FAST=FAST+1 ))
				echo -e "\n\nKilled build (memory freed) switched to j ${FAST} mode!\n\n";
				ninja -C build -j $FAST &> output.txt &
				BUILD_PID=$!;
				STOPPED=1;
			fi
		fi
		

		ps $BUILD_PID > /dev/null;
	done

	echo -e "\n\nFinished\n\n";
else
	echo -e "\n\nCMake Failed!\n\n";
fi
