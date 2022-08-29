#include<cstdio>

int main(){
    char buffer[16];
    while(fgets(buffer, sizeof(buffer), stdin)){
        printf("%s", buffer);
    }
}