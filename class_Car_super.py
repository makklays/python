class Car:
  # Конструктор с параметром по умолчанию year = 2024 
  def __init__(self, brand, model, year = 2024):
    self.brand = brand
    self.model = model
    self.year = year

  def display_info():
    print(f"Автомобиль {self.brand} {self.model}, год: {self.year}")


class ElectricCar(Car):
  # Конструктор подкласса со своим параметром по умолчанию (battery_capacity = 75)
  def __init__(self, brand, model, year, battery_capacity = 75):
    # Вызов конструктора родительского класса 
    super().__init__(brand, model, year)
    self.battery_capacity = battery_capacity  # Новый атрибут подкласса 
    
  def display_info(self):
    print(f"Электромобиль: {self.brand} {self.model}, год выпуска: {self.year}, батарея: {self.battery_capacity} кВт.ч")


# Использование значений по умолчанию в базовом классе 
simple_car = Car("Renault", "Logan")     # year подставится автоматически (2024) 
simple_car.display_info() 

# 2. Создание объекта подкласса со значениями по умолчанию
tesla = ElectricCar("Tesla", "Model Y")  # year=2024, battery_capacity=75
tesla.display_info()

# 3. Передача всех аргументов явно
nissan = ElectricCar("Nissan", "Leaf", 2022, 40)
nissan.display_info()

    
