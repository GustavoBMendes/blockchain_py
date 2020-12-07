from selenium import webdriver
import time

iteracoes = 1000
i = 0

def config(driver):
	driver.get('localhost:5000/config')  # Acessar a URL especificada
	driver.find_element_by_css_selector('#node_address').send_keys("http://127.0.0.1:5001")
	driver.find_element_by_css_selector('#add_node').click()
	time.sleep(2)
	driver.find_element_by_css_selector('#node_address').send_keys("http://127.0.0.1:5002")
	driver.find_element_by_css_selector('#add_node').click()

def transacao(driver, quantia, endere):
	driver.find_element_by_css_selector('#sender_address').send_keys("30819f300d06092a864886f70d010101050003818d0030818902818100ac3a0acd6673164cbaeaa7fd56929a0decfd0a8854bc62f9ce8cd2b1a1d58175ac9e12a8068e73000bc83fb701c8a3b73050f0c401cc72d1c8bc374bcd92ede30947e94e18cc3d57cb986929d090ccd5d9933c89a9e49bfb1292b47d7d8028ce12c1806d2aa5549936fde9c739f0c218209bcaa5bebe1c96d07256d7a263be1f0203010001")
	driver.find_element_by_css_selector('#sender_private_key').send_keys("3082025d02010002818100ac3a0acd6673164cbaeaa7fd56929a0decfd0a8854bc62f9ce8cd2b1a1d58175ac9e12a8068e73000bc83fb701c8a3b73050f0c401cc72d1c8bc374bcd92ede30947e94e18cc3d57cb986929d090ccd5d9933c89a9e49bfb1292b47d7d8028ce12c1806d2aa5549936fde9c739f0c218209bcaa5bebe1c96d07256d7a263be1f020301000102818010066e8ee2237f45b076b91ed77958a04716dc6e070468693a10dc61eedf00e6c42309355d36cff8872020dd946ae8e0d8bc0f4b0da7ca5f3ec0549cd709fedc6406e55729ddd15e317b8957a80774b060d5feccfe989176ce6f8169f0cd991ca915db3606b26fc6a4c791cc6eaacd3ffdd4d35a6de71613a8afc4cda8629a81024100c2be16becd22ea933eafa26ff184bad035948bf80ae934fa5e4976cc1a567b26e9c22b1b43c2567987dd51fda1f726893fa2bc2cd05f6f325b29e1d7cde4f87f024100e266d64067945d6e33ab480fb4ef7e418682307c3c6dd708c4d042150a84b2580f4889211fb5a223dbdebe12f4f3fc553c4a07b3e7565dae6585afcbf9c36a610241009ebfb66af36e732a74ff57bb49769993011a86bf3ca5beba1a02690518b346d101dd76a6532628b80939318d406ae8cf1940df84e897e35d79533af760b036a1024100a85e56037b84489f45e9a1239d29663990b08d223746705e630f85b564271f02820b2d7fe6b70b27a3c1d894fc79de33fd2c08e26fae38e913330273ad00f8c102400be74831751125f46755a28ea834212d8d7c10636db6727ea1388cdde1fdca6eec090f710242d0b3fd2fc29d0eeea97863210c541002002d9eecde6027d04c94")
	driver.find_element_by_css_selector('#recipient_address').send_keys("30819f300d06092a864886f70d010101050003818d00308189028181009edc8e1e720100325448b2a7ca2d806386ec2b149ba1fb11a590379cec3255c9ffb5b09e21d4991211cef187fc456279658a3b428acbd6ad0b0c6ca59962894f31441bcdb42a45062d44a9c63aab757d01be9686533f383ebbddb08af0658cda57de08432eeac7f9b5380b698cce3d5ac807e028973c6745ba39f7ed244ed46b0203010001")
	driver.find_element_by_css_selector('#amount').send_keys(quantia)
	driver.find_element_by_css_selector('#endereco').send_keys(endere)

driver = webdriver.Chrome()  # Inicia o browser
config(driver)
driver.quit()  # Encerra o browser

driver2 = webdriver.Chrome()  # Inicia o browser
driver2.get('localhost:5001/nova_transacao')  # Acessar a URL especificada
transacao(driver2, "1000", "http://127.0.0.1:5000")
#driver3 = webdriver.Chrome()

while i < iteracoes:
	driver2.find_element_by_css_selector('#generate_transaction').click()  # Clica no botão de submit
	#driver3.find_element_by_css_selector('#generate_transaction').click()  # Clica no botão de submit
	i += 1
driver2.quit()  # Encerra o browser
#driver3.quit()  # Encerra o browser

driver4 = webdriver.Chrome()
driver4.get('localhost:5000/minerar')
time.sleep(2)
driver4.find_element_by_css_selector('#mine_button').click()

driver4.quit()
