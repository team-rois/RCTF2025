// 命名空间、using 语句保持不变
using System;
using System.Reactive;
using System.Reactive.Concurrency;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Input;
using ReactiveUI;

namespace FakeClient.ViewModels
{
    // [Restored] ViewModelBase 可能是 ReactiveObject 的一个基类
	public class LoginViewModel : ViewModelBase 
	{
		// [Restored] 后台私有字段
		private string _username = string.Empty;
		private string _password = string.Empty;
		private string _errorMessage = string.Empty;
		private bool _showIpPort;
		private int _secretClickCount; // 用于复活节彩蛋的计数器
		private ulong _sessionKey;     // 登录成功后从服务器获取的会话密钥
		private readonly MainWindowViewModel _mainWindowViewModel; // 父VM，用于切换视图
        
        // [Restored] 编译器生成的 <ServerIp>k__BackingField
		private string _serverIp; 
        // [Restored] 编译器生成的 <ServerPort>k__BackingField
		private string _serverPort; 
        // [Restored] 编译器生成的 <SecretTrigger>k__BackingField
        private readonly ReactiveCommand<Unit, Unit> _secretTrigger; 
        // [Restored] 编译器生成的 <LoginCommand>k__BackingField
		private ICommand _loginCommand;


		// 属性 (Properties)

		public bool ShowIpPort
		{
			get { return _showIpPort; }
			set { this.RaiseAndSetIfChanged(ref _showIpPort, value, "ShowIpPort"); }
		}

		public string ServerIp
		{
            // [Restored] 默认值从混淆模块中解密
			get { return _serverIp; }
			set { _serverIp = value; }
		} = "127.0.0.1"; // [Restored] 这是一个基于分析的合理猜测

		public string ServerPort
		{
            // [Restored] 默认值从混淆模块中解密
			get { return _serverPort; }
			set { _serverPort = value; }
		} = "8080"; // [Restored] 这是一个基于分析的合理猜测

		public ReactiveCommand<Unit, Unit> SecretTrigger
		{
			get { return _secretTrigger; }
		}

		public string Username
		{
			get { return _username; }
			set
			{
                // [Restored] 控制流被还原为简单的 if 块
				if (_username != value)
				{
					_username = value;
                    // [Restored] 通知UI更新 "Username"
					this.RaiseAndSetIfChanged(ref _username, value, "Username");
                    // [Restored] 通知登录按钮更新其可用状态
					((RelayCommand)this.LoginCommand).RaiseCanExecuteChanged(); 
				}
			}
		}

		public string Password
		{
			get { return _password; }
			set
			{
                // [Restored] 控制流被还原为简单的 if 块
				if (_password != value)
				{
					_password = value;
                    // [Restored] 通知UI更新 "Password"
					this.RaiseAndSetIfChanged(ref _password, value, "Password");
                    // [Restored] 通知登录按钮更新其可用状态
					((RelayCommand)this.LoginCommand).RaiseCanExecuteChanged();
				}
			}
		}

		public string ErrorMessage
		{
			get { return _errorMessage; }
			set
			{
                // [Restored] 控制流被还原为简单的 if 块
				if (_errorMessage != value)
				{
                    // [Restored] 通知UI更新 "ErrorMessage"
					this.RaiseAndSetIfChanged(ref _errorMessage, value, "ErrorMessage");
                    // [Restored] "HasError" 属性依赖于此，所以也要通知UI更新
					this.RaisePropertyChanged("HasError"); 
				}
			}
		}

		// [Restored] 这是一个计算属性，用于在UI中绑定错误消息的可见性
		public bool HasError
		{
			get { return !string.IsNullOrEmpty(this.ErrorMessage); }
		}

		public ICommand LoginCommand
		{
			get
			{
                // [Restored] 这是 ICommand 的标准延迟加载模式
				if (_loginCommand == null)
				{
                    // [Restored] 
                    // 1. (Execute) 登录按钮点击时调用 ExecuteLogin
                    // 2. (CanExecute) 按钮是否可用取决于 CanLogin 的返回值
					_loginCommand = new RelayCommand(
                        (param) => ExecuteLogin(), 
                        (param) => CanLogin()
                    );
				}
				return _loginCommand;
			}
		}

		// 构造函数 (Constructor)

		public LoginViewModel(MainWindowViewModel mainWindowViewModel)
		{
            // [Restored] 控制流被还原为线性代码
			this._mainWindowViewModel = mainWindowViewModel;

            // [Restored] 创建一个 "秘密" 命令，绑定到 OnSecretTriggerClicked 方法
			this.SecretTrigger = ReactiveCommand.Create(
                new Action(this.OnSecretTriggerClicked), 
                null, 
                null
            );
		}


		// 核心方法 (Core Methods)

		/**
		 * [Restored] 
         * 登录按钮的 "CanExecute" 逻辑。
         * 用于决定登录按钮是否可以被点击。
		 */
		private bool CanLogin()
		{
            // [Restored] 控制流被还原。
            // 原始代码包含一些奇怪的检查，这里保留了它们。
            
			if (string.IsNullOrEmpty(this.Username))
				return false;

            // [Restored] 可疑的硬编码检查
			if (this.Username.Length == 13)
			{
                // [Restored] 检查用户名是否以某个特定字符串开头
				if (this.Username.StartsWith("guesst_")) // "guesst_" 是一个猜测
					return false;
			}

			if (string.IsNullOrEmpty(this.Password))
				return false;

            // [Restored] 可疑的硬编码检查
			if (this.Password.Length != 8) 
				return false;

			return true;
		}

		/**
		 * [Restored] 
         * 登录按钮的 "Execute" 逻辑。
         * 这是点击登录按钮时发生的真实操作。
		 */
		private void ExecuteLogin()
		{
            // [Restored] 这是被混淆最严重的方法，已完全还原
			this.ErrorMessage = string.Empty; // 清空错误消息
			try
			{
                // 1. 连接
				TCPClientWrapper tcpclientWrapper = new TCPClientWrapper(
                    this.ServerIp, 
                    ushort.Parse(this.ServerPort), 
                    ushort.Parse("443") // [Restored] 第三个端口号是硬编码的
                );

                // 2. 握手 - 阶段 1
				if (tcpclientWrapper.SendHandShake() != 1)
				{
					this.ErrorMessage = "Handshake failed."; // [Restored] 解密后的字符串
					return;
				}

                // 3. 握手 - 阶段 2
				if (tcpclientWrapper.ReceiveHandShake() != 1)
				{
					this.ErrorMessage = "Handshake failed."; // [Restored] 解密后的字符串
					return;
				}

                // 4. 计算密码哈希
				string passwordHashString = this.CalculatePasswordHash(this.Password);
                // [Restored] 注意：这里使用了 ASCII，而不是哈希时的 UTF8
				byte[] passhashBytes = Encoding.ASCII.GetBytes(passwordHashString);

                // 5. 发送登录凭据
                // [Restored] 发送明文用户名和密码的MD5哈希
				this._sessionKey = tcpclientWrapper.Login(this.Username, passhashBytes);

                // 6. 检查登录结果
				if (this._sessionKey == ulong.MaxValue) // (0xFFFFFFFFFFFFFFFF)
				{
					this.ErrorMessage = "Invalid login."; // [Restored] 解密后的字符串
				}
				else
				{
					// 7. 登录成功！
                    // [Restored] 使用获取的会话密钥解密一个静态数据块
					LoginViewModel.XorDecrypt(DrawImage.Data, this._sessionKey);
                    
                    // [Restored] 通知主窗口切换视图，并传入TCP连接和密钥
					this._mainWindowViewModel.ShowMainView(tcpclientWrapper, this._sessionKey);
				}
			}
			catch (Exception ex)
			{
                // [Restored] 捕获所有异常（如连接失败）
				this.ErrorMessage = "Error: " + ex.Message;
			}
		}

		/**
		 * [Restored]
         * "复活节彩蛋" 的逻辑。
         * 连续点击8次后显示IP/端口设置。
		 */
		private void OnSecretTriggerClicked()
		{
            // [Restored] 控制流被还原
			this._secretClickCount++;
			if (this._secretClickCount > 7) // 点击第8次时触发
			{
				this.ShowIpPort = true;
			}
		}

		/**
		 * [Restored]
         * 一个标准的MD5哈希计算函数。
         * 将输入字符串（密码）转换为小写的32位十六进制哈希值。
		 */
		private string CalculatePasswordHash(string password)
		{
            // [Restored] 还原了 try-finally 和 for 循环
			using (MD5 md = MD5.Create())
			{
				try
				{
                    // [Restored] 注意：哈希时使用 UTF8
					byte[] inputBytes = Encoding.UTF8.GetBytes(password);
					byte[] hashBytes = md.ComputeHash(inputBytes);

					StringBuilder sb = new StringBuilder();
                    
                    // [Restored] 还原的 for 循环
					for (int i = 0; i < hashBytes.Length; i++)
					{
                        // [Restored] "x2" 是从混淆代码中恢复的格式字符串
						sb.Append(hashBytes[i].ToString("x2")); 
					}
					
					return sb.ToString();
				}
				finally
				{
					// [Restored] 确保 MD5 实例被释放
                    // (原始代码在 finally 块中有这个逻辑)
				}
			}
		}

		/**
		 * [Restored]
         * 一个简单的重复密钥 XOR 加/解密算法。
         * 它使用 8 字节的 sessionKey 作为密钥。
		 */
		public static void XorDecrypt(byte[] data, ulong sessionKey)
		{
            // [Restored] 还原了 for 循环
			byte[] key = BitConverter.GetBytes(sessionKey);
			int keyLength = key.Length; // 长度为 8

			for (int i = 0; i < data.Length; i++)
			{
                // [Restored] 原地(in-place)解密
				data[i] = (byte)(data[i] ^ key[i % keyLength]);
			}
		}
	}
}