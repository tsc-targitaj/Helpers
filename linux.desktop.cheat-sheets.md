// ########## Тюним десктоп с консоли ##########

// переключаем язык ввода по Alt_Shift
gsettings set org.gnome.desktop.wm.keybindings switch-input-source-backward "['<Alt>Shift_L']"

// сворачиваем окно вторым кликом по иконке в доке
gsettings set org.gnome.shell.extensions.dash-to-dock click-action 'minimize'

// шаг изменения громкости в gnome мультимедийными клавишами
gsettings set org.gnome.settings-daemon.plugins.media-keys volume-step 5

// OSD Volume Number gnome plugin
sudo apt install chrome-gnome-shell
https://extensions.gnome.org/extension/5461/osd-volume-number/
