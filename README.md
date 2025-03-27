# Windows_API_Hooking_by_DLL
DLL로 작성된 Windows API 후킹 
<br>
# 설명
![initial](https://github.com/lastime1650/Windows_API_Hooking_by_DLL/blob/main/images/WindowsDLL.jpg)
<br>
## 이것은 무슨 로직을 가지는가? 
이 API 후킹이 작성된 DLL 코드는 "ntdll.dll"의 몇 API를 후킹하여 "커널 드라이버"에 최종적으로 전달만 하는 로직이 구현되어 있습니다. 
<br> 
## 다음과 같은 로직이 구현
1. API후킹 정보가 담긴 "연결리스트"
2. 각 후킹된 API 마다 최대한 읽을 수 있는 매개변수들을 가져와 연결리스트로 구성
3. (2)에 구성된 연결리스트를 ["길이기반"](https://github.com/lastime1650/Length_Based_Dynamic_Socket_Buffer)으로 '하나의 데이터'로 묶는 작업
4. 커널 드라이버에 전달
5. 비동기적인 API 호출에 대응하기 위해 mutex로 한 차례씩 실행되도록 함.
