cmake_minimum_required (VERSION 3.8)

project("Injector")
add_executable(Injector "Injector/Main.c")

project("Patch")
add_library(Patch SHARED
	"Patch/SigScan.cpp"
	"Patch/DllMain.cpp"
)