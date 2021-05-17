int * global_a;
void func1(){
   global_a = 0x0; // blame
}
void func2(){
    *global_a = 20; // crash here
}
 
void caller1(){
                func1(); // func1 not in bt 
                func2();
}
 
 
int main(){
    caller1(); 
}
