# hkdf-LinaAngelinaG  


В качестве исходных данных для HKDF была выбрана комбинация данных о ozone и о pressure
Потому что эти данные одного порядка, но занимающие разные стороны числовой оси: для того, чтобы данные были как можно менее равномерными

Полученные данные имеют распределение:   
   
   
<img width="707" alt="Снимок экрана 2022-04-20 в 23 50 14" src="https://user-images.githubusercontent.com/61655484/171038941-322b83dd-a5b6-4920-8031-05ae3ec38ceb.png">


Гистограмма для первых 10 битов ключей, сгенерированных с помощью HKDF   
  

<img width="810" alt="Снимок экрана 2022-04-20 в 23 37 57" src="https://user-images.githubusercontent.com/61655484/171038973-10927412-f7c8-45a4-9a86-bb5b63bf196d.png">  
  

Гистограмма для первых 10 битов, сгенерированных по паролям с помощью PBKDF2  
  
  

<img width="763" alt="Снимок экрана 2022-04-20 в 22 08 17" src="https://user-images.githubusercontent.com/61655484/171038995-f028f397-69d8-4cf8-923d-7e9c956c0edb.png">
