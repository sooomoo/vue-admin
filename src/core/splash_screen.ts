
// 在App.vue加载完成之后调用
export const hideSplashScreen = () => {
    const loading = document.getElementById('app_splash_screen')
    if (loading) {
      loading.classList.add('app_splash_screen_fadeOut')
      setTimeout(() => {
        loading.remove()
      }, 300);
    }
}